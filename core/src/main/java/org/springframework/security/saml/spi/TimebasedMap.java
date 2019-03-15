/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.springframework.security.saml.spi;

import java.time.Clock;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

class TimebasedMap<K, V> implements Map<K, V> {

	private Map<K, MapEntry<V>> map = new ConcurrentHashMap<>();
	private long expirationTimeMills = 1000 * 60 * 10;
	private long frequencyIntervalMills = 1000 * 30;
	private AtomicLong lastScan = new AtomicLong(System.currentTimeMillis());
	private Clock time;

	TimebasedMap(Clock time) {
		this.time = time;
	}

	public Clock getTime() {
		return time;
	}

	public TimebasedMap<K, V> setTime(Clock time) {
		this.time = time;
		return this;
	}

	public long getExpirationTimeMills() {
		return expirationTimeMills;
	}

	public TimebasedMap<K, V> setExpirationTimeMills(long expirationTimeMills) {
		this.expirationTimeMills = expirationTimeMills;
		return this;
	}

	public long getFrequencyIntervalMills() {
		return frequencyIntervalMills;
	}

	public TimebasedMap<K, V> setFrequencyIntervalMills(long frequencyIntervalMills) {
		this.frequencyIntervalMills = frequencyIntervalMills;
		return this;
	}

	private V access(MapEntry<V> value) {
		V result = null;
		if (value != null) {
			value.setLastAccessTime(System.currentTimeMillis());
			result = value.getValue();
		}
		return result;
	}

	private boolean isExpired(MapEntry<V> entry) {
		long now = getTime().millis();
		return (now - entry.getLastAccessTime()) > expirationTimeMills;
	}

	private void scanAndRemove() {
		long now = getTime().millis();
		long last = lastScan.get();
		boolean remove = false;
		if ((now - last) > frequencyIntervalMills) {
			remove = lastScan.compareAndSet(last, now);
		}
		if (remove) {
			List<K> possibleRemovals = new LinkedList<>();
			map.entrySet()
				.stream()
				.forEach(
					e -> {
						if (isExpired(e.getValue())) {
							possibleRemovals.add(e.getKey());
						}
					}
				);
			possibleRemovals
				.stream()
				.forEach(
					key -> remove(key)
				);
		}
	}

	@Override
	public int size() {
		scanAndRemove();
		return map.size();
	}

	@Override
	public boolean isEmpty() {
		scanAndRemove();
		return map.isEmpty();
	}

	@Override
	public boolean containsKey(Object key) {
		scanAndRemove();
		return map.containsKey(key);
	}

	@Override
	public boolean containsValue(Object value) {
		scanAndRemove();
		if (value != null) {
			for (Map.Entry<K, MapEntry<V>> entry : map.entrySet()) {
				if (value.equals(entry.getValue().getValue())) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public V get(Object key) {
		scanAndRemove();
		MapEntry<V> value = map.get(key);
		V result = null;
		if (value != null) {
			result = access(value);
		}
		return result;
	}

	@Override
	public V put(K key, V value) {
		scanAndRemove();
		MapEntry<V> entry = new MapEntry<>(value);
		entry = map.put(key, entry);
		if (entry != null) {
			return entry.getValue();
		}
		else {
			return null;
		}
	}

	@Override
	public V remove(Object key) {
		scanAndRemove();
		MapEntry<V> entry = map.remove(key);
		if (entry != null) {
			return entry.getValue();
		}
		else {
			return null;
		}
	}

	@Override
	public void putAll(Map<? extends K, ? extends V> m) {
		scanAndRemove();
		m.entrySet().stream().forEach(
			e -> map.put(e.getKey(), new MapEntry<>(e.getValue()))
		);
	}

	@Override
	public void clear() {
		lastScan.set(System.currentTimeMillis());
		map.clear();
	}

	@Override
	public Set<K> keySet() {
		scanAndRemove();
		return map.keySet();
	}

	@Override
	public Collection<V> values() {
		scanAndRemove();
		return map
			.entrySet()
			.stream()
			.map(
				e -> e.getValue().getValue()
			).collect(toList());
	}

	@Override
	public Set<Entry<K, V>> entrySet() {
		scanAndRemove();
		return
			map.entrySet()
				.stream()
				.map(
					e -> new AbstractMap.SimpleEntry<>(e.getKey(), e.getValue().getValue())
				)
				.collect(Collectors.toSet());
	}

	class MapEntry<V> {

		private V value;
		private long creationTime;
		private long lastAccessTime;

		MapEntry(V value) {
			long now = getTime().millis();
			setValue(value);
			setCreationTime(now);
			setLastAccessTime(now);
		}

		public V getValue() {
			return value;
		}

		public MapEntry<V> setValue(V value) {
			this.value = value;
			return this;
		}

		public long getCreationTime() {
			return creationTime;
		}

		MapEntry<V> setCreationTime(long creationTime) {
			this.creationTime = creationTime;
			return this;
		}

		long getLastAccessTime() {
			return lastAccessTime;
		}

		MapEntry<V> setLastAccessTime(long lastAccessTime) {
			this.lastAccessTime = lastAccessTime;
			return this;
		}
	}
}