use std::sync::{Arc, Condvar, Mutex};

pub struct Future<T> {
    data: Arc<(Mutex<Option<T>>, Condvar)>,
}

impl<T> Future<T> {
    pub fn wait(self) -> T {
        let data = self.data;
        let (data, cvar) = &*data;
        let mut data = data.lock().expect("promise mutex poisoned");
        while (*data).is_none() {
            data = cvar.wait(data).unwrap()
        }
        data.take().unwrap()
    }
}

#[derive(Clone)]
pub struct Promise<T> {
    data: Arc<(Mutex<Option<T>>, Condvar)>,
}

impl<T> Default for Promise<T> {
    fn default() -> Self {
        Self {
            data: Arc::new((Mutex::new(None), Default::default())),
        }
    }
}

impl<T> Promise<T> {
    pub fn resolve(&self, value: T) {
        let (data, cvar) = &*self.data;
        let mut data = data.lock().expect("promise mutex poisoned");
        *data = Some(value);
        cvar.notify_one();
    }

    pub fn get_future(&self) -> Future<T> {
        Future {
            data: self.data.clone(),
        }
    }
}
