//! pasiv-rx (spike): Pasiv's own RandomX CPU miner.
//!
//! The question this answers: does a from-source RandomX miner, signed by Pasiv,
//! survive Windows Defender without an exclusion, at a hashrate near XMRig's?
//! Stock XMRig, even Pasiv-signed, is quarantined on write (2026-10-24).
//!
//! Usage:
//!   pasiv-rx --url [tls://]host:port [--url ...] --user LOGIN [--pass x] [--threads N] [--seconds S]
//!   (several --url = failover, tried in order; `--tls-fingerprint SHA256`
//!   after a tls:// url pins that pool's certificate)
//!   pasiv-rx --bench [--threads N] [--seconds S]
mod net;
mod rx;

use rx::Shared;
use serde_json::{json, Value};
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

const NONCE_AT: usize = 39;
const BATCH: u32 = 512;

#[derive(Clone)]
struct Job {
    id: String,
    blob: Vec<u8>,
    target: u64,
    seed: Vec<u8>,
}

struct Data {
    seed: Vec<u8>,
    cache: Shared<rx::Cache>,
    dataset: Shared<rx::Dataset>,
}

struct Share {
    job_id: String,
    nonce: u32,
    hash: [u8; 32],
}

struct Miner {
    flags: i32,
    threads: usize,
    job: Mutex<Option<(u64, Job)>>,
    generation: AtomicU64,
    data: RwLock<Data>,
    /// The live pool session's share queue; None while disconnected.
    shares: Mutex<Option<mpsc::Sender<Share>>>,
    next_id: AtomicU64,
    hashes: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    stop: AtomicBool,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Pool targets come as 4 bytes (compact) or 8 bytes, little-endian; the
/// hash's last 8 bytes, read the same way, must be below the 64-bit form.
fn parse_target(s: &str) -> Option<u64> {
    let b = unhex(s)?;
    match b.len() {
        4 => {
            let t = u32::from_le_bytes(b.try_into().ok()?) as u64;
            Some(u64::MAX / (0xFFFF_FFFF / t.max(1)))
        }
        8 => Some(u64::from_le_bytes(b.try_into().ok()?)),
        _ => None,
    }
}

fn parse_job(v: &Value) -> Option<Job> {
    Some(Job {
        id: v["job_id"].as_str()?.to_string(),
        blob: unhex(v["blob"].as_str()?)?,
        target: parse_target(v["target"].as_str()?)?,
        seed: unhex(v["seed_hash"].as_str()?)?,
    })
}

impl Miner {
    fn new(threads: usize) -> Arc<Self> {
        let base = unsafe { rx::randomx_get_flags() } | rx::FLAG_FULL_MEM;
        // Large pages when the OS grants them, normal pages otherwise.
        let (flags, dataset) = unsafe {
            let d = rx::randomx_alloc_dataset(base | rx::FLAG_LARGE_PAGES);
            if d.is_null() {
                (base, rx::randomx_alloc_dataset(base))
            } else {
                (base | rx::FLAG_LARGE_PAGES, d)
            }
        };
        assert!(!dataset.is_null(), "could not allocate the 2 GB RandomX dataset");
        let cache = unsafe {
            let c = rx::randomx_alloc_cache(flags);
            if c.is_null() {
                rx::randomx_alloc_cache(flags & !rx::FLAG_LARGE_PAGES)
            } else {
                c
            }
        };
        assert!(!cache.is_null(), "could not allocate the RandomX cache");
        eprintln!(
            "flags={flags:#x} large_pages={} threads={threads}",
            flags & rx::FLAG_LARGE_PAGES != 0
        );
        Arc::new(Miner {
            flags,
            threads,
            job: Mutex::new(None),
            generation: AtomicU64::new(0),
            data: RwLock::new(Data {
                seed: Vec::new(),
                cache: Shared(cache),
                dataset: Shared(dataset),
            }),
            shares: Mutex::new(None),
            next_id: AtomicU64::new(10),
            hashes: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        })
    }

    /// Re-key the dataset for a new seed, in place, across every thread.
    /// Workers hold the read lock per batch, so this waits for them to finish
    /// the batch in hand and then has the whole machine.
    fn ensure_seed(&self, seed: &[u8]) {
        if self.data.read().unwrap().seed == seed {
            return;
        }
        let mut d = self.data.write().unwrap();
        if d.seed == seed {
            return;
        }
        let t0 = Instant::now();
        unsafe { rx::randomx_init_cache(d.cache.0, seed.as_ptr().cast(), seed.len()) };
        let items = unsafe { rx::randomx_dataset_item_count() } as u64;
        let n = self.threads as u64;
        let (cache, ds) = (d.cache, d.dataset);
        std::thread::scope(|s| {
            for i in 0..n {
                let start = items * i / n;
                let end = items * (i + 1) / n;
                s.spawn(move || {
                    let (cache, ds) = (cache, ds);
                    unsafe {
                        rx::randomx_init_dataset(ds.0, cache.0, start as _, (end - start) as _)
                    }
                });
            }
        });
        d.seed = seed.to_vec();
        eprintln!("dataset ready for seed {} in {:.1}s", &hex(seed)[..16], t0.elapsed().as_secs_f32());
    }

    fn set_job(&self, job: Job) {
        let g = self.generation.fetch_add(1, Relaxed) + 1;
        *self.job.lock().unwrap() = Some((g, job));
    }

    fn worker(self: Arc<Self>, idx: u32) {
        let vm = {
            let d = self.data.read().unwrap();
            unsafe { rx::randomx_create_vm(self.flags, d.cache.0, d.dataset.0) }
        };
        assert!(!vm.is_null(), "could not create a RandomX VM");
        let step = self.threads as u32;
        let mut nonce = idx;
        let mut held: u64 = 0;
        let mut out = [0u8; 32];
        while !self.stop.load(Relaxed) {
            let Some((g, job)) = self.job.lock().unwrap().clone() else {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            };
            if g != held {
                held = g;
                nonce = idx;
            }
            let d = self.data.read().unwrap();
            if d.seed != job.seed {
                drop(d);
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            unsafe { rx::randomx_vm_set_dataset(vm, d.dataset.0) };
            let mut cur = job.blob.clone();
            let mut next = job.blob.clone();
            cur[NONCE_AT..NONCE_AT + 4].copy_from_slice(&nonce.to_le_bytes());
            unsafe { rx::randomx_calculate_hash_first(vm, cur.as_ptr().cast(), cur.len()) };
            for _ in 0..BATCH {
                let n2 = nonce.wrapping_add(step);
                next[NONCE_AT..NONCE_AT + 4].copy_from_slice(&n2.to_le_bytes());
                unsafe {
                    rx::randomx_calculate_hash_next(
                        vm,
                        next.as_ptr().cast(),
                        next.len(),
                        out.as_mut_ptr().cast(),
                    )
                };
                let v = u64::from_le_bytes(out[24..32].try_into().unwrap());
                if v < job.target {
                    self.submit(&job.id, nonce, &out);
                }
                nonce = n2;
                std::mem::swap(&mut cur, &mut next);
            }
            // The last hash_first input is discarded: 1 in BATCH, by design.
            drop(d);
            self.hashes.fetch_add(BATCH as u64, Relaxed);
            if self.generation.load(Relaxed) != held {
                continue;
            }
        }
        unsafe { rx::randomx_destroy_vm(vm) };
    }

    fn submit(&self, job_id: &str, nonce: u32, hash: &[u8; 32]) {
        if let Some(tx) = self.shares.lock().unwrap().as_ref() {
            let _ = tx.send(Share { job_id: job_id.to_string(), nonce, hash: *hash });
        }
    }

    fn pool(self: Arc<Self>, endpoints: Vec<net::Endpoint>, user: String, pass: String) {
        let mut i = 0;
        while !self.stop.load(Relaxed) {
            let ep = &endpoints[i % endpoints.len()];
            match self.session(ep, &user, &pass) {
                Ok(()) => {}
                Err(e) => eprintln!("pool {ep}: {e}"),
            }
            *self.shares.lock().unwrap() = None;
            i += 1;
            std::thread::sleep(Duration::from_secs(if i % endpoints.len() == 0 { 5 } else { 1 }));
        }
    }

    fn session(&self, ep: &net::Endpoint, user: &str, pass: &str) -> Result<(), String> {
        let mut conn = net::Conn::connect(ep)?;
        let (tx, rx) = mpsc::channel::<Share>();
        let mut session = String::new();
        conn.send_line(&json!({
            "id": 1, "jsonrpc": "2.0", "method": "login",
            "params": {"login": user, "pass": pass, "agent": "pasiv-rx/0.0.1", "algo": ["rx/0"]}
        }).to_string())?;
        let mut last_ping = Instant::now();
        let mut last_heard = Instant::now();
        while !self.stop.load(Relaxed) {
            while let Ok(s) = rx.try_recv() {
                let id = self.next_id.fetch_add(1, Relaxed);
                conn.send_line(&json!({
                    "id": id, "jsonrpc": "2.0", "method": "submit",
                    "params": {"id": session, "job_id": s.job_id,
                               "nonce": hex(&s.nonce.to_le_bytes()), "result": hex(&s.hash)}
                }).to_string())?;
            }
            if !session.is_empty() && last_ping.elapsed() > Duration::from_secs(60) {
                let id = self.next_id.fetch_add(1, Relaxed);
                conn.send_line(&json!({"id": id, "jsonrpc": "2.0", "method": "keepalived", "params": {"id": session}}).to_string())?;
                last_ping = Instant::now();
            }
            if last_heard.elapsed() > Duration::from_secs(180) {
                return Err("pool silent for 3 minutes".into());
            }
            let Some(line) = conn.read_line()? else { continue };
            last_heard = Instant::now();
            let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
            if msg["method"] == "job" {
                self.on_job(&msg["params"]);
            } else if msg["id"] == 1 {
                if !msg["error"].is_null() {
                    return Err(format!("login refused: {}", msg["error"]));
                }
                let r = &msg["result"];
                session = r["id"].as_str().unwrap_or_default().to_string();
                eprintln!("logged in to {ep}");
                *self.shares.lock().unwrap() = Some(tx.clone());
                self.on_job(&r["job"]);
            } else if msg["id"].as_u64().is_some_and(|i| i >= 10) {
                if msg["error"].is_null() {
                    if msg["result"]["status"] == "OK" {
                        self.accepted.fetch_add(1, Relaxed);
                    }
                } else {
                    self.rejected.fetch_add(1, Relaxed);
                    eprintln!("rejected: {}", msg["error"]);
                }
            }
        }
        Ok(())
    }

    fn on_job(&self, v: &Value) {
        match parse_job(v) {
            Some(job) => {
                self.ensure_seed(&job.seed);
                self.set_job(job);
            }
            None => eprintln!("unparseable job: {v}"),
        }
    }
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let threads = arg(&args, "--threads")
        .and_then(|t| t.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let seconds: Option<u64> = arg(&args, "--seconds").and_then(|s| s.parse().ok());
    let bench = args.iter().any(|a| a == "--bench");

    let m = Miner::new(threads);
    if bench {
        // A fixed seed and a dummy 76-byte blob with an impossible target:
        // pure hashing, no pool, comparable with `xmrig --bench`.
        let seed = vec![0u8; 32];
        m.ensure_seed(&seed);
        m.set_job(Job { id: "bench".into(), blob: vec![7u8; 76], target: 0, seed });
    } else {
        let mut endpoints: Vec<net::Endpoint> = Vec::new();
        for w in args.windows(2) {
            if w[0] == "--url" {
                endpoints.push(net::parse_endpoint(&w[1]).expect("--url [tls://]host:port"));
            } else if w[0] == "--tls-fingerprint" {
                endpoints.last_mut().expect("--tls-fingerprint follows a --url").fingerprint =
                    Some(w[1].clone());
            }
        }
        assert!(!endpoints.is_empty(), "--url [tls://]host:port");
        let user = arg(&args, "--user").expect("--user LOGIN");
        let pass = arg(&args, "--pass").unwrap_or_else(|| "x".into());
        let mp = m.clone();
        std::thread::spawn(move || mp.pool(endpoints, user, pass));
    }
    let workers: Vec<_> = (0..threads as u32)
        .map(|i| {
            let mw = m.clone();
            std::thread::spawn(move || mw.worker(i))
        })
        .collect();

    let start = Instant::now();
    let (mut last_h, mut last_t) = (0u64, Instant::now());
    let mut hashing_since: Option<(Instant, u64)> = None;
    loop {
        std::thread::sleep(Duration::from_secs(10));
        let h = m.hashes.load(Relaxed);
        let rate = (h - last_h) as f64 / last_t.elapsed().as_secs_f64();
        if hashing_since.is_none() && h > 0 {
            hashing_since = Some((Instant::now(), h));
        }
        (last_h, last_t) = (h, Instant::now());
        println!(
            "{:>5}s  {:>9.1} H/s  accepted {}  rejected {}",
            start.elapsed().as_secs(),
            rate,
            m.accepted.load(Relaxed),
            m.rejected.load(Relaxed)
        );
        if seconds.is_some_and(|s| start.elapsed().as_secs() >= s) {
            if let Some((t, h0)) = hashing_since {
                println!(
                    "average {:.1} H/s over {:.0}s of hashing",
                    (h - h0) as f64 / t.elapsed().as_secs_f64(),
                    t.elapsed().as_secs_f64()
                );
            }
            m.stop.store(true, Relaxed);
            break;
        }
    }
    for w in workers {
        let _ = w.join();
    }
}
