use std::collections::BTreeMap;

pub struct ObjectMap<T> {
    map: Option<BTreeMap<usize, T>>,
    counter: usize,
}

impl<T> ObjectMap<T> {
    pub const fn new() -> Self {
        Self {
            map: None,
            counter: 1usize,
        }
    }

    fn next_key(&mut self) -> usize {
        let key = self.counter;
        self.counter += 1usize;
        key
    }

    pub fn remove(&mut self, key: &usize) -> Option<T> {
        match &mut self.map {
            Some(map) => map.remove(key),
            None => None,
        }
    }

    pub fn insert(&mut self, val: T) -> usize {
        let key = self.next_key();
        match &mut self.map {
            Some(map) => {
                if map.insert(key, val).is_some() {
                    panic!()
                }
            }
            None => {
                let mut map = BTreeMap::new();
                map.insert(key, val);
                self.map = Some(map);
            }
        }
        key
    }

    pub fn get(&self, key: &usize) -> Option<&T> {
        match &self.map {
            Some(map) => map.get(key),
            None => None,
        }
    }

    pub fn get_mut(&mut self, key: &usize) -> Option<&mut T> {
        match &mut self.map {
            Some(map) => map.get_mut(key),
            None => None,
        }
    }
}
