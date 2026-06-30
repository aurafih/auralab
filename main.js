        
        const $ = id => document.getElementById(id);
        
        const setEl = (id, prop, val) => { const el = $(id); if (el) el[prop] = val; };
        
        const uuid = () => {
            if (crypto.randomUUID) return crypto.randomUUID();
            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
                const r = Math.random() * 16 | 0; const v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
        };
        const Sys = {
            ctx: null, wake: null,
            vibrate(ms) { try { if (navigator.vibrate) navigator.vibrate(ms); } catch (e) {  } },
            async wakeLock() {
                if (!navigator.wakeLock) return;
                try { this.wake = await navigator.wakeLock.request('screen'); }
                catch (e) {  }
            },
            async wakeUnlock() {
                if (this.wake) { try { await this.wake.release(); } catch (e) { } this.wake = null; }
            },
            toast(msg, undoCallback) {
                const t = $('toast');
                if (!t) return;
                t.innerHTML = `<span style="flex-grow:1">${Sys.escapeHTML(msg)}</span>`;
                if (undoCallback) {
                    const btn = document.createElement('button');
                    btn.innerText = 'Undo';
                    btn.style.cssText = 'background:var(--accent); color:#fff; font-size:12px; padding:6px 12px; min-height:0; border-radius:12px; font-weight:600; margin-left:8px;';
                    btn.onclick = (e) => {
                        e.stopPropagation();
                        try { undoCallback(); } catch (e) { console.error('Undo callback failed:', e); }
                        t.classList.remove('show');
                    };
                    t.appendChild(btn);
                }
                t.classList.add('show');
                clearTimeout(this.toastT);
                this.toastT = setTimeout(() => t.classList.remove('show'), undoCallback ? 5000 : 2000);
            },
            escapeHTML: str => String(str == null ? '' : str).replace(/[&<>'"]/g, tag => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'}[tag] || tag))
        };

        // --- WEBCRYPTO API (PBKDF2 + AES-GCM) ---
        const Crypt = {
            async derive(p, s) {
                if (!crypto.subtle) throw new Error('WebCrypto unavailable (requires HTTPS or localhost)');
                return await crypto.subtle.deriveKey(
                    { name: "PBKDF2", salt: s, iterations: 100000, hash: "SHA-256" },
                    await crypto.subtle.importKey("raw", new TextEncoder().encode(p), "PBKDF2", false, ["deriveKey"]),
                    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
                );
            },
            async enc(d, p) {
                const s = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
                const c = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await this.derive(p, s), new TextEncoder().encode(JSON.stringify(d)));
                return { c: Array.from(new Uint8Array(c)), i: Array.from(iv), s: Array.from(s) };
            },
            async dec(o, p) {
                try {
                    if (!o || !o.c || !o.i || !o.s) return null;
                    return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt(
                        { name: "AES-GCM", iv: new Uint8Array(o.i) },
                        await this.derive(p, new Uint8Array(o.s)),
                        new Uint8Array(o.c)
                    )));
                } catch (e) { return null; }
            }
        };

        // --- INDEXEDDB STORAGE ---
        const DB = {
            db: null,
            async init() {
                return new Promise((resolve, reject) => {
                    if (!('indexedDB' in window)) { reject(new Error('IndexedDB not supported')); return; }
                    let req;
                    try { req = indexedDB.open('VaultFit_V4', 2); }
                    catch (e) { reject(e); return; }
                    req.onupgradeneeded = e => {
                        const db = e.target.result;
                        if (!db.objectStoreNames.contains('s')) db.createObjectStore('s');
                    };
                    req.onsuccess = e => { this.db = e.target.result; resolve(); };
                    req.onerror = e => {
                        console.error("IndexedDB error:", e.target.error);
                        reject(e.target.error || new Error('IndexedDB request failed'));
                    };
                    req.onblocked = e => {
                        console.warn("IndexedDB blocked — close other tabs of this app and reload");
                        reject(new Error('IndexedDB upgrade blocked by another tab'));
                    };
                });
            },
            async get(k) {
                return new Promise((resolve, reject) => {
                    if (!this.db) { reject(new Error('DB not initialised — call DB.init() first')); return; }
                    let rq;
                    try { rq = this.db.transaction('s').objectStore('s').get(k); }
                    catch (e) { reject(e); return; }
                    rq.onsuccess = () => resolve(rq.result);
                    rq.onerror = () => reject(rq.error || new Error('DB.get failed'));
                });
            },
            async set(k, v) {
                return new Promise((resolve, reject) => {
                    if (!this.db) { reject(new Error('DB not initialised — call DB.init() first')); return; }
                    const tx = this.db.transaction('s', 'readwrite');
                    tx.objectStore('s').put(v, k);
                    tx.oncomplete = () => resolve();
                    tx.onerror = () => reject(tx.error || new Error('DB.set failed'));
                    tx.onabort = () => reject(tx.error || new Error('DB.set aborted'));
                });
            },
            async clear() {
                return new Promise((resolve, reject) => {
                    if (!this.db) { reject(new Error('DB not initialised — call DB.init() first')); return; }
                    const tx = this.db.transaction('s', 'readwrite');
                    tx.objectStore('s').clear();
                    tx.oncomplete = () => resolve();
                    tx.onerror = () => reject(tx.error || new Error('DB.clear failed'));
                    tx.onabort = () => reject(tx.error || new Error('DB.clear aborted'));
                });
            }
        };

        // --- STATE MANAGER ---
        const Store = {
            pin: null, locked: true,
            data: { routines: [], history: [], lastId: null },
            settings: { theme: 'dark', auto: true },
            _saveInFlight: false,
            _savePending: null,
            // Serialised save: collapses rapid successive calls into one write.
            // The latest data snapshot wins; older in-flight writes are awaited but their data is superseded.
            async save() {
                if (!this.pin) { console.warn('Store.save called without a PIN — skipping'); return; }
                // Capture the latest snapshot we want persisted
                this._savePending = { snapshot: this.data, settingsSnapshot: this.settings };
                // If a save is already in flight, the loop below will pick up the latest pending snapshot
                if (this._saveInFlight) return;
                this._saveInFlight = true;
                try {
                    while (this._savePending) {
                        const pending = this._savePending;
                        this._savePending = null;
                        try {
                            const enc = await Crypt.enc(pending.snapshot, this.pin);
                            await DB.set('vault', enc);
                            await DB.set('settings', pending.settingsSnapshot);
                        } catch (e) {
                            console.error('Store.save failed:', e);
                            Sys.toast('Save failed — changes may not persist');
                            break; // stop the loop; user will be notified
                        }
                    }
                } finally {
                    this._saveInFlight = false;
                }
            },
            nav(id) {
                const target = $(id);
                if (!target) { console.warn('Store.nav: view not found:', id); return; }
                document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
                target.classList.remove('hidden');
            }
        };

        // --- AUTH FLOW ---
        const Auth = {
            fails: parseInt(localStorage.getItem('vf_fails') || 0),
            lockoutTimer: null,
            _submitting: false,
            checkLockout() {
                clearInterval(this.lockoutTimer);
                this.lockoutTimer = null;
                const check = () => {
                    const lockoutUntil = parseInt(localStorage.getItem('vf_lockout') || 0);
                    const remMs = lockoutUntil - Date.now();
                    const pinEl = $('pin-input'), btnEl = $('btn-auth'), errEl = $('auth-err');
                    if (!pinEl || !btnEl || !errEl) return;
                    if (remMs > 0) {
                        const secs = Math.ceil(remMs / 1000);
                        const mins = Math.floor(secs / 60);
                        const remSecs = secs % 60;
                        const timeStr = `${mins}:${String(remSecs).padStart(2, '0')}`;
                        pinEl.disabled = true;
                        btnEl.disabled = true;
                        errEl.innerText = `Locked. Try again in ${timeStr}`;
                        errEl.classList.remove('hidden');
                    } else {
                        pinEl.disabled = false;
                        btnEl.disabled = false;
                        errEl.classList.add('hidden');
                        clearInterval(this.lockoutTimer);
                        this.lockoutTimer = null;
                    }
                };
                check();
                this.lockoutTimer = setInterval(check, 1000);
            },
            async init() {
                try {
                    await DB.init();
                    const btnEl = $('btn-auth');
                    if (btnEl) btnEl.disabled = false;
                    const pinEl = $('pin-input');
                    if (pinEl) {
                        pinEl.addEventListener('keyup', e => { if (e.key === 'Enter') this.submit(); });
                    }
                    const set = await DB.get('settings');
                    if (set) { Store.settings = { ...Store.settings, ...set }; Settings.apply(); }
                    const v = await DB.get('vault');
                    const authMsg = $('auth-msg');
                    if (!v && authMsg) authMsg.innerText = "Create a new PIN (data is heavily encrypted locally)";
                    this.checkLockout();
                } catch (error) {
                    console.error("Failed to initialize database:", error);
                    const authMsg = $('auth-msg');
                    if (authMsg) authMsg.innerText = "Error: Failed to load database. Please reload or check console.";
                    const btnEl = $('btn-auth');
                    if (btnEl) btnEl.disabled = true;
                }
            },
            async submit() {
                // Guard against double-submit (e.g. rapid Enter keypresses / double-tap)
                if (this._submitting) return;
                const lockoutUntil = parseInt(localStorage.getItem('vf_lockout') || 0);
                if (Date.now() < lockoutUntil) {
                    this.checkLockout();
                    return;
                }

                const pinEl = $('pin-input');
                if (!pinEl) return;
                const p = pinEl.value;
                if (p.length < 4 || /^(0000|1234|1111)$/.test(p)) return this.err("PIN is too weak or too short");

                this._submitting = true;
                const btnEl = $('btn-auth');
                if (btnEl) btnEl.disabled = true;
                try {
                    const v = await DB.get('vault');
                    if (!v) {
                        Store.pin = p; await Store.save(); this.ok(); Sys.toast("Vault Created");
                    } else {
                        const d = await Crypt.dec(v, p);
                        if (d) {
                            // Ensure decrypted data has the expected shape; fall back to defaults for missing fields
                            Store.data = {
                                routines: Array.isArray(d.routines) ? d.routines : [],
                                history: Array.isArray(d.history) ? d.history : [],
                                lastId: d.lastId || null
                            };
                            Store.pin = p;
                            this.fails = 0;
                            localStorage.setItem('vf_fails', 0);
                            localStorage.removeItem('vf_lockout');
                            this.ok();
                        } else {
                            this.fails++; localStorage.setItem('vf_fails', this.fails);
                            if (this.fails >= 5) {
                                localStorage.setItem('vf_lockout', Date.now() + 5 * 60000);
                                this.checkLockout();
                            } else if (this.fails >= 3) {
                                localStorage.setItem('vf_lockout', Date.now() + 1 * 60000);
                                this.checkLockout();
                            } else {
                                this.err(`Wrong PIN (${3 - this.fails} attempts before lockout)`);
                            }
                        }
                    }
                } catch (e) {
                    console.error('Auth.submit failed:', e);
                    this.err('Unlock failed. Please try again.');
                } finally {
                    this._submitting = false;
                    // Re-enable button unless we're now locked out (checkLockout manages disabled state)
                    const stillLocked = parseInt(localStorage.getItem('vf_lockout') || 0) > Date.now();
                    if (btnEl && !stillLocked) btnEl.disabled = false;
                }
            },
            err(m) {
                setEl('auth-err', 'innerText', m);
                const errEl = $('auth-err'); if (errEl) errEl.classList.remove('hidden');
                const pinEl = $('pin-input'); if (pinEl) pinEl.value = '';
            },
            ok() {
                const pinEl = $('pin-input'); if (pinEl) pinEl.value = '';
                const errEl = $('auth-err'); if (errEl) errEl.classList.add('hidden');
                Store.locked = false;
                App.tab('main');
                this.setupIdle();
            },
            setupIdle() {
                if (this._idleSetup) return; this._idleSetup = true;
                let t; const r = () => {
                    clearTimeout(t);
                    t = setTimeout(() => {
                        const vActive = $('v-active'), vRest = $('v-rest');
                        const inWorkout = (vActive && !vActive.classList.contains('hidden')) ||
                                          (vRest && !vRest.classList.contains('hidden'));
                        if (inWorkout) r(); 
                        else if (!Store.locked) App.lock();
                    }, 15 * 60000);
                };
                window.addEventListener('touchstart', r); window.addEventListener('click', r); r();
            }
        };

        
        const App = {
            tab(t) {
                if (Store.locked) return;
                const target = $('v-' + t);
                if (!target) { console.warn('App.tab: unknown tab', t); return; }
                Store.nav('v-' + t);
                document.querySelectorAll('.tab-bar button').forEach(b => {
                    b.classList.remove('active');
                    const oc = b.getAttribute('onclick') || '';
                    if (oc.includes(`('${t}')`)) b.classList.add('active');
                });
                try {
                    if (t === 'main') Dashboard.render();
                    else if (t === 'history') History.render();
                    else if (t === 'settings') Settings.render();
                } catch (e) { console.error(`App.tab('${t}') render failed:`, e); }
            },
            lock() {
                
                if (Auth.lockoutTimer) { clearInterval(Auth.lockoutTimer); Auth.lockoutTimer = null; }
                Store.locked = true;
                Store.data = null;
                Store.pin = null;
                Store.nav('v-auth');
            },
            confirm(msg, cb, cancelCb) {
                const modal = $('modal'), mdlMsg = $('mdl-msg'), mdlYes = $('mdl-yes'), mdlNo = $('mdl-no');
                if (!modal || !mdlMsg || !mdlYes || !mdlNo) { 
                    
                    if (window.confirm(msg)) try { cb(); } catch (e) { console.error(e); }
                    return;
                }
                mdlMsg.innerText = msg;
                modal.classList.remove('hidden');
                mdlYes.onclick = () => { modal.classList.add('hidden'); try { cb(); } catch (e) { console.error('Confirm yes failed:', e); } };
                mdlNo.onclick = () => { modal.classList.add('hidden'); if (cancelCb) try { cancelCb(); } catch (e) { console.error('Confirm no failed:', e); } };
            }
        };

        
        const Dashboard = {
            render() {
                const list = $('routines-list');
                if (!list) return;
                if (!Store.data || !Array.isArray(Store.data.routines)) { list.innerHTML = ''; return; }
                list.innerHTML = '';
                if (Store.data.routines.length === 0) {
                    list.innerHTML = `<div class="card center text-sub p-6">No routines found. Tap "Create Routine" to begin.</div>`;
                }
                Store.data.routines.forEach(r => {
                    if (!r || !r.id) return; 
                    const el = document.createElement('div'); el.className = 'card flex between align-center pointer';
                    el.innerHTML = `<div><h2 class="mb-2">${Sys.escapeHTML(r.n || 'Untitled')}</h2><p class="text-sub">${(r.e || []).length} exercises</p></div>
                                <div class="flex gap-2">
                                  <button class="btn-panel" style="padding:16px 12px" onclick="Creator.clone('${r.id}')"><svg class="icon icon-sm" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>
                                  <button class="btn-panel" style="padding:16px 12px" onclick="Creator.openEdit('${r.id}')"><svg class="icon icon-sm" viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                                  <button class="btn-panel" style="padding:16px 12px" onclick="Dashboard.shareRoutine('${r.id}')"><svg class="icon icon-sm" viewBox="0 0 24 24"><path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8M16 6l-4-4-4 4M12 2v13"/></svg></button>
                                  <button class="btn-primary" style="padding:16px 20px" onclick="Active.start('${r.id}')"><svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke:none;fill:#fff"><polygon points="5 3 19 12 5 21 5 3"/></svg></button>
                                </div>`;
                    list.appendChild(el);
                });

                const banner = $('last-workout-banner'), nameEl = $('last-w-name');
                if (banner && nameEl) {
                    const last = Store.data.lastId && Store.data.routines.find(x => x.id === Store.data.lastId);
                    if (last) {
                        nameEl.innerText = last.n || 'Untitled';
                        banner.classList.remove('hidden');
                    } else {
                        banner.classList.add('hidden');
                    }
                }
            },
            resumeLast() {
                if (!Store.data || !Store.data.lastId) { Sys.toast('No recent workout to resume'); return; }
                Active.start(Store.data.lastId);
            },
            async shareRoutine(id) {
                const r = Store.data && Store.data.routines.find(x => x.id === id);
                if (!r) { Sys.toast('Routine not found'); return; }
                const json = JSON.stringify({ routines: [r] }, null, 2);
                const safeName = (r.n || 'routine').replace(/\\s+/g, '_').toLowerCase();
                if (navigator.share) {
                    try {
                        const file = new File([json], `${safeName}_routine.json`, { type: 'application/json' });
                        await navigator.share({ files: [file], title: r.n || 'Routine', text: 'Here is my routine for VaultFit!' });
                        return;
                    } catch (e) {  }
                }
                const blob = new Blob([json], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                try {
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${safeName}_routine.json`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    Sys.toast("Routine JSON Downloaded");
                } finally {
                    
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                }
            }
        };

        
        const Creator = {
            id: null, ex: [],
            _saving: false,
            openNew() { this.id = null; this.ex = []; setEl('cr-title', 'innerText', 'New Routine'); setEl('cr-name', 'value', ''); const delBtn = $('btn-del-routine'); if (delBtn) delBtn.classList.add('hidden'); this.render(); Store.nav('v-create'); },
            openEdit(id) {
                const r = Store.data && Store.data.routines.find(x => x.id === id);
                if (r) { this.id = id; this.ex = JSON.parse(JSON.stringify(r.e || [])); setEl('cr-name', 'value', r.n || ''); setEl('cr-title', 'innerText', 'Edit'); const delBtn = $('btn-del-routine'); if (delBtn) delBtn.classList.remove('hidden'); this.render(); Store.nav('v-create'); }
                else { Sys.toast('Routine not found'); }
            },
            clone(id) {
                const r = Store.data && Store.data.routines.find(x => x.id === id);
                if (r) { this.id = null; this.ex = JSON.parse(JSON.stringify(r.e || [])); setEl('cr-name', 'value', (r.n || 'Untitled') + ' (Copy)'); setEl('cr-title', 'innerText', 'Clone'); const delBtn = $('btn-del-routine'); if (delBtn) delBtn.classList.add('hidden'); this.render(); Store.nav('v-create'); }
                else { Sys.toast('Routine not found'); }
            },
            typeChange() {
                const sel = $('cr-ex-type'), tgt = $('cr-ex-target');
                if (!sel || !tgt) return;
                tgt.placeholder = sel.value === 'reps' ? 'Target Reps' : 'Hold Time (s)';
            },
            addEx() {
                const nameEl = $('cr-ex-name');
                if (!nameEl) return;
                const n = nameEl.value.trim();
                if (!n) return Sys.toast('Exercise Name required');
                const typeEl = $('cr-ex-type'), setsEl = $('cr-ex-sets'), tgtEl = $('cr-ex-target'), restEl = $('cr-ex-rest');
                const newEx = {
                    n,
                    t: (typeEl && typeEl.value === 'time') ? 'time' : 'reps',
                    s: Math.max(1, parseInt(setsEl && setsEl.value) || 3),
                    tgt: Math.max(1, parseInt(tgtEl && tgtEl.value) || 10),
                    r: Math.max(5, parseInt(restEl && restEl.value) || 60)
                };
                this.ex.push(newEx);
                nameEl.value = '';
                try { nameEl.focus(); } catch (e) { }
                this.render();
                setTimeout(() => { const v = $('v-create'); if (v) v.scrollTop = v.scrollHeight; }, 100);
                Sys.toast(`Added ${newEx.n}`, () => {
                    this.ex.pop();
                    this.render();
                });
            },
            delEx(i) {
                if (i < 0 || i >= this.ex.length) return;
                const deletedEx = this.ex[i];
                this.ex.splice(i, 1);
                this.render();
                Sys.toast(`Removed ${deletedEx.n}`, () => {
                    this.ex.splice(i, 0, deletedEx);
                    this.render();
                });
            },
            render() {
                const l = $('cr-list'); if (!l) return;
                l.innerHTML = '';
                setEl('cr-ex-count', 'innerText', `${this.ex.length} items`);
                this.ex.forEach((x, i) => {
                    if (!x) return;
                    const el = document.createElement('div'); el.className = 'card flex between align-center pointer'; el.style.borderLeft = "4px solid var(--accent)";
                    el.draggable = true;
                    el.ondragstart = e => { try { e.dataTransfer.setData('text/plain', String(i)); e.dataTransfer.effectAllowed = 'move'; } catch (_) {} setTimeout(() => el.style.opacity = 0.5, 0); };
                    el.ondragend = () => { el.style.opacity = 1; };
                    el.ondragover = e => { e.preventDefault(); el.classList.add('drag-over'); };
                    el.ondragleave = () => { el.classList.remove('drag-over'); };
                    el.ondrop = e => {
                        e.preventDefault(); el.classList.remove('drag-over');
                        const from = parseInt(e.dataTransfer.getData('text/plain'));
                        if (!isNaN(from) && from !== i && from >= 0 && from < this.ex.length) {
                            const oldEx = [...this.ex];
                            const item = this.ex.splice(from, 1)[0];
                            this.ex.splice(i, 0, item);
                            this.render();
                            Sys.toast("Reordered playlist", () => {
                                this.ex = oldEx;
                                this.render();
                            });
                        }
                    };
                    el.innerHTML = `<div><h3 class="mb-2"><span class="text-sub mr-2">${i + 1}.</span> ${Sys.escapeHTML(x.n)}</h3><p class="text-sub" style="font-size:12px">${x.s} sets x ${x.tgt} ${x.t === 'reps' ? 'reps' : 'sec'} • ${x.r}s rest</p></div>
                                <div class="flex gap-2 align-center">
                                    <span class="text-sub mr-2" style="cursor:grab; display:flex; align-items:center;"><svg class="icon" viewBox="0 0 24 24" style="width:20px;height:20px"><circle cx="8" cy="6" r="1.5" fill="currentColor" stroke="none"/><circle cx="16" cy="6" r="1.5" fill="currentColor" stroke="none"/><circle cx="8" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="16" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="8" cy="18" r="1.5" fill="currentColor" stroke="none"/><circle cx="16" cy="18" r="1.5" fill="currentColor" stroke="none"/></svg></span>
                                    <button class="p-2 text-red" style="font-size:18px;" onclick="Creator.delEx(${i})"><svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke:var(--red)"><path d="M18 6L6 18M6 6l12 12"/></svg></button>
                                </div>`;
                    l.appendChild(el);
                });
            },
            cancel() { App.confirm("Discard unsaved changes?", () => App.tab('main')); },
            async save() {
                if (this._saving) return; 
                const nameEl = $('cr-name');
                const n = nameEl ? nameEl.value.trim() : '';
                if (!n || !this.ex.length) return Sys.toast('Give it a name and some exercises!');
                this._saving = true;
                try {
                    if (this.id) { const i = Store.data.routines.findIndex(x => x.id === this.id); if (i > -1) Store.data.routines[i] = { id: this.id, n, e: this.ex }; }
                    else { Store.data.routines.push({ id: uuid(), n, e: this.ex }); }
                    await Store.save(); Sys.toast("Routine Saved!"); App.tab('main');
                } catch (e) {
                    console.error('Creator.save failed:', e);
                    Sys.toast('Save failed — please try again');
                } finally {
                    this._saving = false;
                }
            },
            async delRoutine() {
                if (!this.id) return;
                const routineId = this.id;
                App.confirm("Permanently delete routine?", async () => {
                    try {
                        const deletedRoutine = Store.data.routines.find(x => x.id === routineId);
                        if (!deletedRoutine) return;
                        const index = Store.data.routines.findIndex(x => x.id === routineId);
                        Store.data.routines = Store.data.routines.filter(x => x.id !== routineId);
                        const oldLastId = Store.data.lastId;
                        if (Store.data.lastId === routineId) Store.data.lastId = null;
                        await Store.save();

                        Sys.toast("Routine deleted", async () => {
                            try {
                                Store.data.routines.splice(index, 0, deletedRoutine);
                                Store.data.lastId = oldLastId;
                                await Store.save();
                                Dashboard.render();
                                Sys.toast("Routine restored");
                            } catch (e) {
                                console.error('Restore failed:', e);
                                Sys.toast('Restore failed');
                            }
                        });

                        App.tab('main');
                    } catch (e) {
                        console.error('delRoutine failed:', e);
                        Sys.toast('Delete failed');
                    }
                });
            }
        };

        
        
        const RING_CIRC = 804;
        const Active = {
            rtn: null, exIdx: 0, set: 1, reps: 0,
            clickTimer: null, raf: null, ts: 0, swTimer: null, startTime: 0,
            log: [], pausedElap: 0, isPaused: false, isPrep: false, _skipPrepTriggered: false,
            autoTimer: null, lastSetState: null,

            
            
            _clearTimers() {
                cancelAnimationFrame(this.raf); this.raf = null;
                clearTimeout(this.autoTimer); this.autoTimer = null;
            },
            start(id) {
                if (!Store.data || !Array.isArray(Store.data.routines)) { Sys.toast('No data available'); return; }
                this.rtn = Store.data.routines.find(x => x.id === id);
                if (!this.rtn || !Array.isArray(this.rtn.e) || this.rtn.e.length === 0) {
                    this.rtn = null; 
                    Sys.toast('Routine has no exercises');
                    return;
                }
                
                this._clearTimers();
                clearInterval(this.swTimer); this.swTimer = null;
                this.lastSetState = null;
                this.isPrep = false; this.isPaused = false; this._skipPrepTriggered = false;

                Store.data.lastId = id; Store.save();
                this.exIdx = 0; this.set = 1; this.reps = 0; this.log = [];
                Sys.wakeLock();
                this.startTime = Date.now();
                setEl('act-stopwatch', 'innerText', '00:00');
                this.swTimer = setInterval(() => {
                    if (!this.startTime) return;
                    const d = Math.floor((Date.now() - this.startTime) / 1000);
                    setEl('act-stopwatch', 'innerText', `${String(Math.floor(d / 60)).padStart(2, '0')}:${String(d % 60).padStart(2, '0')}`);
                }, 1000);
                this.load(); Store.nav('v-active');

                
                const c = $('act-clicker');
                if (!c) return;
                c.onpointerdown = e => {
                    if (this.isPrep) {
                        this._skipPrepTriggered = true;
                        this.isPrep = false;
                        cancelAnimationFrame(this.raf); this.raf = null;
                        setEl('act-unit', 'innerText', 'Seconds');
                        const ex = this.rtn && this.rtn.e[this.exIdx];
                        if (!ex) return;
                        this.reps = ex.tgt;
                        this.ts = Date.now();
                        this.isPaused = false;
                        this.tickTime();
                        return;
                    }
                    this._skipPrepTriggered = false;
                    c.style.transform = 'scale(0.92)';
                };
                c.onpointerup = () => {
                    c.style.transform = 'none';
                    if (this._skipPrepTriggered) {
                        this._skipPrepTriggered = false;
                        return;
                    }
                    this.inc();
                };
                c.onpointerleave = () => { c.style.transform = 'none'; };
            },
            _currentEx() {
                if (!this.rtn || !Array.isArray(this.rtn.e)) return null;
                if (this.exIdx < 0 || this.exIdx >= this.rtn.e.length) return null;
                return this.rtn.e[this.exIdx];
            },
            adjRest(s) {
                const ex = this._currentEx();
                if (!ex) return;
                ex.r = Math.max(5, (ex.r || 60) + s);
                setEl('act-rest-val', 'innerText', ex.r);
            },
            load() {
                const ex = this._currentEx();
                if (!ex) return;
                setEl('act-name', 'innerText', ex.n || 'Exercise');
                setEl('act-set', 'innerText', this.set);
                setEl('act-max-sets', 'innerText', ex.s);
                setEl('act-target', 'innerText', ex.tgt);
                setEl('act-unit', 'innerText', ex.t === 'reps' ? 'Reps' : 'Seconds');
                setEl('act-rest-val', 'innerText', ex.r);
                this.reps = 0;
                this.isPaused = false;

                if (ex.t === 'time') {
                    this.isPrep = true;
                    this.ts = Date.now();
                    const ring = $('act-ring'); if (ring) ring.style.strokeDashoffset = RING_CIRC;
                    setEl('act-counter', 'innerText', '5');
                    setEl('act-unit', 'innerText', 'Prep...');
                    cancelAnimationFrame(this.raf); this.raf = null;
                    this.tickPrep();
                } else {
                    this.isPrep = false;
                    cancelAnimationFrame(this.raf); this.raf = null;
                    const ring = $('act-ring'); if (ring) ring.style.strokeDashoffset = RING_CIRC;
                    this.ui();
                }
            },
            tickPrep() {
                const elap = (Date.now() - this.ts) / 1000;
                const rem = Math.ceil(5 - elap);
                if (rem > 0) {
                    setEl('act-counter', 'innerText', rem);
                    this.raf = requestAnimationFrame(() => this.tickPrep());
                } else {
                    this.isPrep = false;
                    const ex = this._currentEx();
                    if (!ex) return;
                    setEl('act-unit', 'innerText', 'Seconds');
                    this.reps = ex.tgt;
                    this.ts = Date.now();
                    this.tickTime();
                }
            },
            ui() {
                setEl('act-counter', 'innerText', this.reps);
                const ex = this._currentEx();
                if (!ex) return;
                if (ex.t === 'reps') {
                    const pct = Math.min(this.reps / Math.max(1, ex.tgt), 1);
                    const ring = $('act-ring'); if (ring) ring.style.strokeDashoffset = RING_CIRC - (RING_CIRC * pct);
                    if (Store.settings.auto && this.reps >= ex.tgt) {
                        clearTimeout(this.autoTimer);
                        this.autoTimer = setTimeout(() => this.finishSet(), 400);
                    }
                }
            },
            tickTime() {
                if (this.isPaused) return;
                const ex = this._currentEx();
                if (!ex) return;
                const elap = (Date.now() - this.ts) / 1000;
                const newReps = Math.max(Math.ceil(ex.tgt - elap), 0);
                this.reps = newReps;
                const pct = Math.min(elap / Math.max(0.001, ex.tgt), 1);
                const ring = $('act-ring'); if (ring) ring.style.strokeDashoffset = RING_CIRC - (RING_CIRC * pct);
                setEl('act-counter', 'innerText', this.reps);
                if (this.reps <= 0) { this.finishSet(); }
                else { this.raf = requestAnimationFrame(() => this.tickTime()); }
            },
            inc() {
                const ex = this._currentEx();
                if (!ex) return;
                if (ex.t === 'reps') {
                    this.reps++; this.ui();
                } else if (ex.t === 'time') {
                    this.isPaused = !this.isPaused;
                    if (this.isPaused) {
                        cancelAnimationFrame(this.raf); this.raf = null;
                        this.pausedElap = (Date.now() - this.ts) / 1000;
                        setEl('act-unit', 'innerText', 'Paused');
                    } else {
                        this.ts = Date.now() - (this.pausedElap * 1000);
                        setEl('act-unit', 'innerText', 'Seconds');
                        this.tickTime();
                    }
                }
            },
            decrement() { if (this.reps > 0 && this._currentEx() && this._currentEx().t === 'reps') { this.reps--; this.ui(); } },
            reset() { this.reps = 0; this.ui(); Sys.toast("Counter Reset"); },

            finishSet() {
                const restEl = $('v-rest');
                if (restEl && !restEl.classList.contains('hidden')) return; 
                cancelAnimationFrame(this.raf); this.raf = null;
                clearTimeout(this.autoTimer); this.autoTimer = null;
                const ex = this._currentEx();
                if (!ex) return;
                const loggedVal = ex.t === 'time' ? Math.max(ex.tgt - this.reps, 0) : this.reps;
                this.log.push({ n: ex.n, s: this.set, r: loggedVal, t: ex.t });

                this.lastSetState = {
                    exIdx: this.exIdx,
                    set: this.set,
                    reps: this.reps
                };

                Rest.start(ex.r);
                Sys.toast(`Set ${this.set} logged: ${loggedVal} ${ex.t === 'reps' ? 'reps' : 's'}`, () => this.undoLastSet());
            },
            undoLastSet() {
                if (!this.lastSetState) return;
                Rest.skipQuietly();
                if (this.log.length > 0) this.log.pop();
                this.exIdx = this.lastSetState.exIdx;
                this.set = this.lastSetState.set;
                this.reps = this.lastSetState.reps;
                this.lastSetState = null;
                this.load();
                Store.nav('v-active');
                Sys.toast("Logged reps undone");
            },
            nextPhase() {
                
                if (!this.rtn) return;
                const ex = this._currentEx();
                if (!ex) { this.finishWorkout(); return; }
                if (this.set < ex.s) { this.set++; this.load(); }
                else if (this.exIdx < this.rtn.e.length - 1) { this.exIdx++; this.set = 1; this.load(); }
                else { this.finishWorkout(); }
            },
            prevPhase() {
                if (!this.rtn) return;
                if (this.log.length > 0) this.log.pop();
                if (this.set > 1) {
                    this.set--;
                    this.load();
                } else if (this.exIdx > 0) {
                    this.exIdx--;
                    const prevEx = this.rtn.e[this.exIdx];
                    this.set = prevEx ? prevEx.s : 1;
                    this.load();
                } else {
                    this.set = 1;
                    this.load();
                }
            },
            prev() { clearTimeout(this.autoTimer); this.autoTimer = null; cancelAnimationFrame(this.raf); this.raf = null; this.prevPhase(); },
            skip() { clearTimeout(this.autoTimer); this.autoTimer = null; cancelAnimationFrame(this.raf); this.raf = null; this.nextPhase(); },
            quit() {
                App.confirm("End workout early and discard history?", () => {
                    this._clearTimers();
                    clearInterval(this.swTimer); this.swTimer = null;
                    this.startTime = 0;
                    this.rtn = null; 
                    this.log = [];
                    Sys.wakeUnlock();
                    Rest.skipQuietly();
                    App.tab('main');
                });
            },

            async finishWorkout() {
                if (!this.rtn) { console.warn('finishWorkout called without an active routine'); return; }
                clearInterval(this.swTimer); this.swTimer = null;
                this._clearTimers();
                Sys.wakeUnlock();

                
                const dur = Math.floor((Date.now() - this.startTime) / 1000);
                this.startTime = 0;
                if (!Store.data || !Array.isArray(Store.data.history)) Store.data.history = [];
                Store.data.history.unshift({ id: uuid(), d: Date.now(), n: this.rtn.n, dur, log: this.log });
                if (Store.data.history.length > 100) Store.data.history.pop();
                try { await Store.save(); }
                catch (e) { console.error('Failed to persist workout history:', e); Sys.toast('History save failed'); }

                
                try {
                    const c = $('confetti');
                    if (c) {
                        const ctx = c.getContext('2d');
                        c.width = Math.max(1, document.body.clientWidth);
                        c.height = Math.max(1, document.body.clientHeight);
                        c.classList.remove('hidden');
                        const p = Array.from({ length: 150 }).map(() => ({
                            x: c.width / 2 + ((Math.random() - 0.5) * 100),
                            y: c.height / 2 + ((Math.random() - 0.5) * 100),
                            vx: (Math.random() - 0.5) * 30,
                            vy: (Math.random() - 1) * 30,
                            c: 'hsl(0,0%,' + (40 + Math.random() * 60) + '%)',
                            s: Math.random() * 12 + 6
                        }));
                        const anim = () => {
                            ctx.clearRect(0, 0, c.width, c.height); let alive = false;
                            p.forEach(i => {
                                i.x += i.vx; i.y += i.vy; i.vy += 0.6;
                                if (i.y < c.height) alive = true;
                                ctx.fillStyle = i.c; ctx.fillRect(i.x, i.y, i.s, i.s);
                            });
                            if (alive) requestAnimationFrame(anim); else c.classList.add('hidden');
                        };
                        anim();
                    }
                } catch (e) { console.warn('Confetti animation skipped:', e); }

                const completedName = this.rtn.n;
                this.rtn = null; 
                this.log = [];
                App.confirm(`Workout Complete!\n${completedName} finished in ${Math.floor(dur / 60)}m ${dur % 60}s.`, () => App.tab('history'));
            }
        };

        
        const PlateCalc = {
            open() {
                const overlay = $('v-plates');
                if (!overlay) return;
                overlay.classList.remove('hidden');
                const tgt = $('pc-target'); if (tgt) { try { tgt.focus(); } catch (e) {} }
                this.calc();
            },
            calc() {
                const tgtEl = $('pc-target'), barEl = $('pc-bar'), r = $('pc-result');
                if (!tgtEl || !barEl || !r) return;
                const tgt = parseFloat(tgtEl.value) || 0;
                const bar = parseFloat(barEl.value) || 20;
                r.innerHTML = '';
                if (!tgt) { r.innerHTML = '<span class="text-sub">Enter target weight</span>'; return; }
                if (tgt <= bar) { r.innerHTML = '<span class="text-sub">Target must be > Bar</span>'; return; }
                let rem = (tgt - bar) / 2;
                const plates = [25, 20, 15, 10, 5, 2.5, 1.25];
                const needed = [];
                plates.forEach(p => { let count = Math.floor(rem / p); if (count > 0) { needed.push({ p, count }); rem -= count * p; } });
                if (needed.length === 0) { r.innerHTML = '<span class="text-sub">No plates needed</span>'; return; }
                let html = '<div class="text-sub mb-2" style="font-size:14px">Per side:</div><div class="flex gap-2 center flex-wrap mt-2">';
                needed.forEach(n => {
                    for (let i = 0; i < n.count; i++) {
                        let c = '#555';
                        if (n.p >= 25) c = '#999'; else if (n.p >= 20) c = '#777'; else if (n.p >= 15) c = '#bbb'; else if (n.p >= 10) c = '#888'; else c = '#666';
                        html += `<div class="center" style="width:40px; height:40px; border-radius:50%; background:${c}; color:#fff; font-weight:bold; font-size:12px; box-shadow:0 4px 10px rgba(0,0,0,0.5)">${n.p}</div>`;
                    }
                });
                html += '</div>';
                if (rem > 0) html += `<div class="text-sub mt-4" style="font-size:12px">Remaining: ${+(rem * 2).toFixed(2)}kg (no micro-plates)</div>`;
                r.innerHTML = html;
            }
        };

        
        const Rest = {
            tot: 0, left: 0, t: null, ts: 0, _lastRem: -1, isPaused: false, pausedLeft: 0,
            start(sec) {
                
                const ex = Active._currentEx ? Active._currentEx() : null;
                if (!ex) { console.warn('Rest.start called without an active exercise'); return; }
                clearInterval(this.t);
                const safeSec = Math.max(1, parseInt(sec) || 60);
                this.tot = safeSec; this.left = safeSec; this.ts = Date.now(); this._lastRem = -1;
                this.isPaused = false;
                const btnPause = $('btn-rest-pause');
                if (btnPause) btnPause.innerText = "Pause";
                setEl('rest-next', 'innerText',
                    Active.set < ex.s ? `${ex.n} (Set ${Active.set + 1})`
                    : (Active.exIdx < Active.rtn.e.length - 1 ? (Active.rtn.e[Active.exIdx + 1].n || 'Next') : "Final Phase")
                );
                const vRest = $('v-rest'); if (vRest) vRest.classList.remove('hidden');
                this.tick();
                this.t = setInterval(() => { if (!this.isPaused) this.tick(); }, 100);
            },
            togglePause() {
                this.isPaused = !this.isPaused;
                const btnPause = $('btn-rest-pause');
                if (this.isPaused) {
                    if (btnPause) btnPause.innerText = "Resume";
                    this.pausedLeft = this.left;
                } else {
                    if (btnPause) btnPause.innerText = "Pause";
                    this.ts = Date.now() - ((this.tot - this.pausedLeft) * 1000);
                }
            },
            tick() {
                this.left = this.tot - (Date.now() - this.ts) / 1000;
                const rem = Math.ceil(this.left);
                if (rem > 0 && rem <= 3 && this._lastRem !== rem) {
                    this._lastRem = rem;
                }

                if (this.left <= 0) return this.skip();
                setEl('rest-counter', 'innerText', Math.max(0, rem));
                
                
                const ring = $('rest-ring');
                if (ring) {
                    const ratio = Math.max(0, Math.min(1, this.left / Math.max(0.001, this.tot)));
                    ring.style.strokeDashoffset = RING_CIRC - (RING_CIRC * ratio);
                }
            },
            adjust(s) { this.tot = Math.max(5, this.tot + s); this.tick(); },
            skip() {
                clearInterval(this.t); this.t = null;
                const vRest = $('v-rest'); if (vRest) vRest.classList.add('hidden');
                
                if (Active && Active.rtn && typeof Active.nextPhase === 'function') Active.nextPhase();
            },
            skipQuietly() {
                clearInterval(this.t); this.t = null;
                const vRest = $('v-rest'); if (vRest) vRest.classList.add('hidden');
            }
        };

        
        const History = {
            render() {
                if (!Store.data || !Array.isArray(Store.data.history)) return;
                setEl('stat-total-w', 'innerText', Store.data.history.length);

                
                
                const graph = $('history-graph');
                if (graph) {
                    const today = new Date(); today.setHours(23, 59, 59, 999);
                    const days = Array.from({ length: 7 }).map((_, i) => {
                        const d = new Date(today.getTime() - (6 - i) * 86400000);
                        return { d: d, start: d.getTime() - 86400000, end: d.getTime(), count: 0 };
                    });
                    Store.data.history.forEach(h => {
                        if (typeof h.d !== 'number') return;
                        days.forEach(day => { if (h.d > day.start && h.d <= day.end) day.count++; });
                    });
                    const maxCnt = Math.max(1, ...days.map(d => d.count));
                    let graphHtml = '';
                    days.forEach((day, i) => {
                        const pct = (day.count / maxCnt) * 100;
                        const lbl = day.d.toLocaleDateString(undefined, { weekday: 'short' }).charAt(0);
                        graphHtml += `<div class="bar-wrap">
                        <span style="font-size:10px; color:var(${day.count > 0 ? '--text' : '--sub'})">${day.count > 0 ? day.count : ''}</span>
                        <div class="bar" style="height: ${Math.max(2, pct)}%; background: ${day.count > 0 ? 'var(--accent)' : 'var(--border)'}"></div>
                        <span class="bar-lbl" style="${i === 6 ? 'color:var(--text);font-weight:bold' : ''}">${Sys.escapeHTML(lbl)}</span>
                    </div>`;
                    });
                    graph.innerHTML = graphHtml;
                }

                const l = $('history-list'); if (!l) return;
                l.innerHTML = '';
                if (Store.data.history.length === 0) {
                    l.innerHTML = `<div class="center text-sub p-6">Complete a workout to see history here.</div>`;
                    return;
                }
                Store.data.history.forEach((h, i) => {
                    if (!h || !h.id) return; 
                    const el = document.createElement('div'); el.className = 'card';
                    const logArr = Array.isArray(h.log) ? h.log : [];
                    let logHtml = '';
                    if (logArr.length > 0) {
                        logHtml = `<div class="mt-4 pt-4 hidden" id="log-detail-${i}" style="border-top: 1px solid var(--border); font-size: 14px;">`;
                        logArr.forEach(item => {
                            if (!item) return;
                            const unit = item.t ? (item.t === 'time' ? 'sec' : 'reps') : 'reps/sec';
                            logHtml += `<div class="flex between text-sub mb-1">
                            <span>${Sys.escapeHTML(item.n)} (Set ${item.s})</span>
                            <span style="color:var(--text)">${Sys.escapeHTML(String(item.r))} ${unit}</span>
                        </div>`;
                        });
                        logHtml += `</div>
                    <button class="text-accent w-100 mt-2 pointer" style="font-size: 14px; padding: 4px;" onclick="
                        const d = document.getElementById('log-detail-${i}');
                        if (!d) return;
                        d.classList.toggle('hidden');
                        this.innerText = d.classList.contains('hidden') ? 'Show Details' : 'Hide Details';
                    ">Show Details</button>`;
                    }
                    const durStr = `${Math.floor((h.dur || 0) / 60)}m ${(h.dur || 0) % 60}s`;
                    el.innerHTML = `
                    <div class="flex between mb-2">
                        <h3 style="color:var(--accent); font-size:18px">${Sys.escapeHTML(h.n || 'Workout')}</h3>
                        <div class="flex gap-2 align-center">
                            <span class="text-sub">${new Date(h.d || Date.now()).toLocaleDateString()}</span>
                            <button class="text-red pointer" style="padding:4px; min-height:0; display:flex; align-items:center;" onclick="History.delete('${h.id}')"><svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke:var(--red)"><path d="M18 6L6 18M6 6l12 12"/></svg></button>
                        </div>
                    </div>
                    <p class="text-sub mb-2">Duration: ${durStr} • ${logArr.length} sets completed</p>
                    ${logHtml}
                `;
                    l.appendChild(el);
                });
            },
            async delete(id) {
                if (!Store.data || !Array.isArray(Store.data.history)) return;
                const index = Store.data.history.findIndex(x => x.id === id);
                if (index === -1) return;
                const deletedHistory = Store.data.history[index];
                Store.data.history.splice(index, 1);
                try {
                    await Store.save();
                    History.render();
                } catch (e) {
                    console.error('History.delete save failed:', e);
                    
                    Store.data.history.splice(index, 0, deletedHistory);
                    Sys.toast('Delete failed — please try again');
                    return;
                }

                Sys.toast("Workout deleted", async () => {
                    try {
                        Store.data.history.splice(index, 0, deletedHistory);
                        await Store.save();
                        History.render();
                        Sys.toast("Workout restored");
                    } catch (e) {
                        console.error('History restore failed:', e);
                        Sys.toast('Restore failed');
                    }
                });
            }
        };

        
        const Settings = {
            apply() {
                const themeEl = $('set-theme'), autoEl = $('set-auto');
                if (themeEl) themeEl.checked = Store.settings.theme === 'dark';
                if (autoEl) autoEl.checked = !!Store.settings.auto;
                const theme = Store.settings.theme === 'light' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', theme);
                
                try { localStorage.setItem('vf_theme', theme); } catch (e) {  }
            },
            render() { this.apply(); },
            toggleTheme() {
                const themeEl = $('set-theme');
                Store.settings.theme = (themeEl && themeEl.checked) ? 'dark' : 'light';
                document.documentElement.setAttribute('data-theme', Store.settings.theme);
                try { localStorage.setItem('vf_theme', Store.settings.theme); } catch (e) {}
                Store.save();
            },
            bind() {
                ['auto'].forEach(k => {
                    const el = $(`set-${k}`);
                    if (!el) return;
                    el.onchange = e => { Store.settings[k] = e.target.checked; Store.save(); };
                });
            },
            export() {
                try {
                    const blob = new Blob([JSON.stringify(Store.data)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `vaultfit_backup_${Date.now()}.json`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                } catch (e) {
                    console.error('Settings.export failed:', e);
                    Sys.toast('Export failed');
                }
            },
            import(e) {
                const f = e.target && e.target.files && e.target.files[0];
                if (!f) return;
                
                if (f.size > 50 * 1024 * 1024) {
                    Sys.toast('Backup file too large (max 50MB)');
                    e.target.value = '';
                    return;
                }
                App.confirm("Warning: Importing a backup will overwrite your current routines and history. Continue?", () => {
                    const r = new FileReader();
                    r.onload = async ev => {
                        try {
                            const d = JSON.parse(ev.target.result);
                            
                            
                            if (!d || typeof d !== 'object') throw new Error('Not an object');
                            if (!Array.isArray(d.routines) || !Array.isArray(d.history)) {
                                throw new Error('Missing routines/history arrays');
                            }
                            Store.data = {
                                routines: d.routines,
                                history: d.history,
                                lastId: d.lastId || null
                            };
                            await Store.save();
                            Sys.toast("Database Imported");
                            App.tab('settings');
                        } catch (err) {
                            console.error('Settings.import failed:', err);
                            Sys.toast('Invalid backup file');
                        }
                        e.target.value = '';
                    };
                    r.onerror = () => { Sys.toast('Failed to read file'); e.target.value = ''; };
                    r.readAsText(f);
                }, () => { e.target.value = ''; });
            },
            async reset() {
                App.confirm("CRITICAL: Wipe all local data and routines?", async () => {
                    try {
                        await DB.clear();
                        try { localStorage.removeItem('vf_theme'); localStorage.removeItem('vf_fails'); localStorage.removeItem('vf_lockout'); } catch (e) {}
                        location.reload();
                    } catch (e) {
                        console.error('Settings.reset failed:', e);
                        Sys.toast('Reset failed — please try again');
                    }
                });
            }
        };


        
        
        
        const Peer = {
            pc: null,
            dc: null,
            _onData: null,
            _onOpen: null,
            _onClose: null,
            _onError: null,
            _chunks: [],
            _expectedSize: 0,

            config: {
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' }
                ]
            },

            reset() {
                if (this.dc) { try { this.dc.close(); } catch (e) { } this.dc = null; }
                if (this.pc) { try { this.pc.close(); } catch (e) { } this.pc = null; }
                this._chunks = []; this._expectedSize = 0;
            },

            _safeLocalDescription() {
                if (!this.pc || !this.pc.localDescription) return '{}';
                return JSON.stringify(this.pc.localDescription);
            },

            
            async createOffer() {
                if (typeof RTCPeerConnection === 'undefined') throw new Error('WebRTC not supported in this browser');
                this.reset();
                this.pc = new RTCPeerConnection(this.config);
                this.dc = this.pc.createDataChannel('sync', { ordered: true });
                this._setupDC(this.dc);

                const offer = await this.pc.createOffer();
                await this.pc.setLocalDescription(offer);

                
                await new Promise(resolve => {
                    if (!this.pc) return resolve();
                    if (this.pc.iceGatheringState === 'complete') return resolve();
                    const check = () => {
                        if (this.pc && this.pc.iceGatheringState === 'complete') {
                            this.pc.removeEventListener('icegatheringstatechange', check);
                            resolve();
                        }
                    };
                    this.pc.addEventListener('icegatheringstatechange', check);
                    setTimeout(resolve, 5000);
                });

                return this._safeLocalDescription();
            },

            
            async acceptOffer(offerStr) {
                if (typeof RTCPeerConnection === 'undefined') throw new Error('WebRTC not supported in this browser');
                this.reset();
                this.pc = new RTCPeerConnection(this.config);

                this.pc.ondatachannel = (event) => {
                    this.dc = event.channel;
                    this._setupDC(this.dc);
                };

                const offer = JSON.parse(offerStr);
                if (!offer || !offer.type) throw new Error('Invalid offer');
                await this.pc.setRemoteDescription(new RTCSessionDescription(offer));
                const answer = await this.pc.createAnswer();
                await this.pc.setLocalDescription(answer);

                await new Promise(resolve => {
                    if (!this.pc) return resolve();
                    if (this.pc.iceGatheringState === 'complete') return resolve();
                    const check = () => {
                        if (this.pc && this.pc.iceGatheringState === 'complete') {
                            this.pc.removeEventListener('icegatheringstatechange', check);
                            resolve();
                        }
                    };
                    this.pc.addEventListener('icegatheringstatechange', check);
                    setTimeout(resolve, 5000);
                });

                return this._safeLocalDescription();
            },

            
            async acceptAnswer(answerStr) {
                if (!this.pc) throw new Error('No peer connection');
                const answer = JSON.parse(answerStr);
                if (!answer || !answer.type) throw new Error('Invalid answer');
                await this.pc.setRemoteDescription(new RTCSessionDescription(answer));
            },

            _setupDC(dc) {
                dc.binaryType = 'arraybuffer';
                dc.onopen = () => { if (this._onOpen) try { this._onOpen(); } catch (e) { console.error('Peer onOpen handler failed:', e); } };
                dc.onclose = () => { if (this._onClose) try { this._onClose(); } catch (e) { console.error('Peer onClose handler failed:', e); } };
                dc.onerror = (ev) => {
                    console.error('Data channel error:', ev);
                    if (this._onError) try { this._onError(ev); } catch (e) { console.error('Peer onError handler failed:', e); }
                };
                dc.onmessage = (e) => {
                    
                    const msg = typeof e.data === 'string' ? e.data : null;
                    if (msg) {
                        try {
                            const parsed = JSON.parse(msg);
                            if (parsed && parsed._chunk) {
                                
                                this._chunks.push(parsed.data);
                                if (parsed.idx === parsed.total - 1) {
                                    const full = this._chunks.join('');
                                    this._chunks = [];
                                    if (this._onData) try { this._onData(full); } catch (e) { console.error('Peer onData handler failed:', e); }
                                }
                                return;
                            }
                        } catch (err) {  }
                        if (this._onData) try { this._onData(msg); } catch (e) { console.error('Peer onData handler failed:', e); }
                    }
                };
            },

            send(data) {
                if (!this.dc || this.dc.readyState !== 'open') return false;
                let str;
                try { str = typeof data === 'string' ? data : JSON.stringify(data); }
                catch (e) { console.error('Peer.send: failed to serialise data', e); return false; }
                
                const CHUNK = 14000;
                try {
                    if (str.length <= CHUNK) {
                        this.dc.send(str);
                    } else {
                        const total = Math.ceil(str.length / CHUNK);
                        for (let i = 0; i < total; i++) {
                            this.dc.send(JSON.stringify({
                                _chunk: true,
                                idx: i,
                                total: total,
                                data: str.substring(i * CHUNK, (i + 1) * CHUNK)
                            }));
                        }
                    }
                    return true;
                } catch (e) {
                    
                    
                    console.error('Peer.send failed (channel may be saturated):', e);
                    return false;
                }
            },

            onData(cb) { this._onData = cb; },
            onOpen(cb) { this._onOpen = cb; },
            onClose(cb) { this._onClose = cb; },
            onError(cb) { this._onError = cb; },

            isConnected() {
                return !!(this.dc && this.dc.readyState === 'open');
            }
        };

        
        
        
        const Signal = {
            es: null,
            topicS: '',
            topicR: '',
            _onDisconnect: null,
            init(pin, isSender, onMessage, onDisconnect) {
                this.close();
                if (typeof EventSource === 'undefined') {
                    console.error('EventSource not supported — signaling unavailable');
                    if (onDisconnect) try { onDisconnect(); } catch (e) {}
                    return;
                }
                
                const safePin = String(pin).replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
                if (!safePin) {
                    console.error('Signal.init: invalid pin');
                    if (onDisconnect) try { onDisconnect(); } catch (e) {}
                    return;
                }
                this.topicS = `vf_sig_${safePin}_` + (isSender ? 'S' : 'R');
                this.topicR = `vf_sig_${safePin}_` + (isSender ? 'R' : 'S');
                this._onDisconnect = onDisconnect || null;
                try {
                    this.es = new EventSource(`https://ntfy.sh/${this.topicR}/sse`);
                } catch (e) {
                    console.error('EventSource construction failed:', e);
                    if (onDisconnect) try { onDisconnect(); } catch (_) {}
                    return;
                }
                this.es.onmessage = (e) => {
                    try {
                        const data = JSON.parse(e.data);
                        if (data && data.event === 'message' && typeof data.message === 'string') {
                            try { onMessage(JSON.parse(data.message)); }
                            catch (err) { console.warn('Signal: dropped malformed message', err); }
                        }
                    } catch (err) {  }
                };
                this.es.onerror = (ev) => {
                    
                    
                    console.warn('Signal EventSource error — browser will auto-retry', ev);
                };
            },
            async send(msgObj) {
                try {
                    const resp = await fetch(`https://ntfy.sh/${this.topicS}`, {
                        method: 'POST',
                        body: JSON.stringify(msgObj)
                    });
                    if (!resp.ok) console.warn('Signal.send non-OK response:', resp.status);
                } catch (e) {
                    console.error('Signal.send failed:', e);
                }
            },
            close() {
                if (this.es) { try { this.es.close(); } catch (e) {} this.es = null; }
                this._onDisconnect = null;
            }
        };

        
        
        
        const SyncUI = {
            mode: 'encrypted', role: null, step: 0, syncPin: null,

            open() {
                Store.nav('v-sync');
                this.role = null; this.step = 0; this.syncPin = null;
                this._renderRoleSelect();
            },

            close() {
                Signal.close();
                Peer.reset();
                App.tab('settings');
            },

            _renderRoleSelect() {
                $('sync-content').innerHTML = `
                <div class="sync-hero">
                    <span class="sync-pill encrypted"><svg class="icon icon-sm" viewBox="0 0 24 24" style="vertical-align:-3px"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Device-to-Device Sync</span>
                    <h1 class="mb-2" style="margin-top:16px">Transfer Data</h1>
                    <p class="text-sub">Securely sync your vault to another device.</p>
                </div>
                <div style="padding: 0 16px; margin-bottom: 20px;">
                    <input type="password" id="sync-pin-input" placeholder="Enter sync PIN (min 4 chars)" class="mb-2 center" style="font-size:18px; letter-spacing:4px;">
                    <p class="text-sub" style="font-size:11px; text-align:center;">Both devices must enter the same PIN to encrypt/decrypt data</p>
                </div>
                <div class="sync-role-btns">
                    <div class="sync-role-btn" onclick="SyncUI.selectRole('send')">
                        <span class="role-icon"><svg class="icon icon-xl" viewBox="0 0 24 24"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg></span>
                        <h3>Export from this device</h3>
                        <p>Send data to another device</p>
                    </div>
                    <div class="sync-role-btn" onclick="SyncUI.selectRole('receive')">
                        <span class="role-icon"><svg class="icon icon-xl" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg></span>
                        <h3>Import to this device</h3>
                        <p>Receive data from another device</p>
                    </div>
                </div>`;
            },

            async selectRole(role) {
                this.role = role;
                Sys.vibrate(15);
                const pinEl = $('sync-pin-input');
                if (!pinEl || pinEl.value.length < 4) {
                    Sys.toast('Enter a sync PIN (min 4 chars)');
                    if (pinEl) { try { pinEl.focus(); } catch (e) {} }
                    return;
                }
                this.syncPin = pinEl.value;
                try {
                    if (role === 'send') await this._startSender();
                    else await this._startReceiver();
                } catch (e) {
                    console.error('SyncUI.selectRole failed:', e);
                    this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--red)"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>', 'Setup Failed', e.message || 'Unexpected error');
                }
            },

            async _startSender() {
                const pin = Math.floor(100000 + Math.random() * 900000).toString();
                $('sync-content').innerHTML = `
                    <div class="sync-hero">
                        <span class="sync-pill encrypted"><svg class="icon icon-sm" viewBox="0 0 24 24" style="vertical-align:-3px"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Encrypted · Export</span>
                        <h2 style="margin-top:16px" class="mb-2">Your Transfer PIN</h2>
                        <div style="font-size: 48px; letter-spacing: 8px; font-weight: bold; margin: 24px 0; color: var(--accent);">${pin}</div>
                        <p class="text-sub">Enter this PIN on the receiving device to connect.</p>
                    </div>`;

                Signal.init(pin, true, async (msg) => {
                    if (msg.t === 'ready') {
                        try {
                            const offerStr = await Peer.createOffer();
                            Signal.send({ t: 'offer', d: offerStr });
                        } catch (e) { this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--red)"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>', 'Connection Failed', e.message); }
                    } else if (msg.t === 'answer') {
                        try { await Peer.acceptAnswer(msg.d); Signal.close(); }
                        catch (e) { this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--red)"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>', 'Connection Failed', e.message); }
                    }
                });
                Peer.onOpen(() => this._senderConnected());
            },

            _senderConnected() {
                this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--green)"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>', 'Connected!', 'Transferring encrypted vault...', true);
                setTimeout(async () => {
                    try {
                        if (!this.syncPin || !Store.data) throw new Error('Missing PIN or data');
                        const encrypted = await Crypt.enc(Store.data, this.syncPin);
                        const ok = Peer.send(JSON.stringify({ t: 'sync_enc', d: encrypted }));
                        if (!ok) {
                            this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--red)"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>', 'Send Failed', 'Data channel closed before transfer. Please try again.');
                            return;
                        }
                        Peer.onData((msg) => {
                            try {
                                const resp = JSON.parse(msg);
                                if (resp.t === 'ack') this._renderComplete('send');
                                else this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--red)"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>', 'Sync Failed', resp.msg || 'Receiver reported an error');
                            } catch (e) {
                                console.error('Sender: failed to parse receiver response', e);
                            }
                        });
                    } catch (e) {
                        console.error('_senderConnected transfer failed:', e);
                        this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--red)"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>', 'Transfer Failed', e.message || 'Encryption failed');
                    }
                }, 800);
            },

            async _startReceiver() {
                $('sync-content').innerHTML = `
                <div class="sync-hero">
                    <span class="sync-pill encrypted"><svg class="icon icon-sm" viewBox="0 0 24 24" style="vertical-align:-3px"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Encrypted · Import</span>
                    <h2 style="margin-top:16px" class="mb-2">Enter Transfer PIN</h2>
                    <p class="text-sub">Enter the 6-digit PIN shown on the sending device</p>
                </div>
                <div style="padding: 0 16px;">
                    <input type="number" id="transfer-pin-input" placeholder="000000" class="mb-4 center" style="font-size:32px; letter-spacing:8px; width: 100%; border: 1px solid var(--border); background: var(--panel); color: var(--text); padding: 16px; border-radius: 12px; appearance: textfield;" maxlength="6">
                    <button class="btn-primary w-100" onclick="SyncUI._receiverConnect()">Connect & Receive</button>
                </div>`;
            },

            async _receiverConnect() {
                const pinEl = $('transfer-pin-input');
                if (!pinEl) return;
                const pin = pinEl.value.trim();
                if (!/^\d{6}$/.test(pin)) return Sys.toast('Enter the 6-digit transfer PIN');

                this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>', 'Connecting...', 'Contacting sender...', true);

                
                
                if (this._connectTimer) clearTimeout(this._connectTimer);
                this._connectTimer = setTimeout(() => {
                    if (Peer.isConnected()) return;
                    this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--red)"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>', 'Connection Timeout', 'The sender did not respond within 60 seconds. Please verify the PIN and try again.');
                    Signal.close();
                }, 60000);

                Signal.init(pin, false, async (msg) => {
                    if (msg.t === 'offer') {
                        if (this._connectTimer) { clearTimeout(this._connectTimer); this._connectTimer = null; }
                        this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>', 'Connecting...', 'Accepting secure connection...', true);
                        try {
                            const answerStr = await Peer.acceptOffer(msg.d);

                            
                            Peer.onOpen(() => { });
                            Peer.onData((m) => {
                                this._receiverGotData(m);
                            });

                            Signal.send({ t: 'answer', d: answerStr });
                            Signal.close();
                        } catch (e) {
                            this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--red)"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>', 'Failed', 'Could not establish connection. ' + (e.message || 'Unknown error'));
                        }
                    }
                });

                Signal.send({ t: 'ready' });
            },

            async _receiverGotData(msg) {
                try {
                    const payload = JSON.parse(msg);

                    if (payload.t === 'sync_enc') {
                        
                        this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 019.9-1"/></svg>', 'Decrypting...', 'Decrypting received data with your PIN...', true);
                        const decrypted = await Crypt.dec(payload.d, this.syncPin);
                        if (!decrypted) {
                            Peer.send(JSON.stringify({ t: 'err', msg: 'Decryption failed: PIN mismatch' }));
                            this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--red)"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>', 'PIN Mismatch', 'Could not decrypt data. Both devices must use the same sync PIN.');
                            return;
                        }

                        
                        this._showImportPreview(decrypted, true);

                    } else if (payload.t === 'sync_simple') {
                        
                        this._showImportPreview(payload.d, false);
                    }

                } catch (e) {
                    this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24" style="stroke:var(--red)"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>', 'Error', 'Failed to process received data: ' + e.message);
                }
            },

            _showImportPreview(data, isEncrypted) {
                const routineCount = data.routines ? data.routines.length : 0;
                const historyCount = data.history ? data.history.length : 0;

                let previewHtml = '<div class="sync-data-preview">';
                if (data.routines && data.routines.length > 0) {
                    previewHtml += '<div style="font-weight:600; margin-bottom:8px; color:var(--accent)"><svg class="icon icon-sm" viewBox="0 0 24 24" style="vertical-align:-3px"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg> Routines (' + routineCount + ')</div>';
                    data.routines.forEach(r => {
                        previewHtml += `<div class="sync-data-row"><span>${this._escapeHtml(r.n)}</span><span class="text-sub">${r.e ? r.e.length : '?'} exercises</span></div>`;
                    });
                }
                if (data.history && data.history.length > 0) {
                    previewHtml += '<div style="font-weight:600; margin-top:12px; margin-bottom:8px; color:var(--green)"><svg class="icon icon-sm" viewBox="0 0 24 24" style="vertical-align:-3px"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 2v4M16 2v4"/></svg> History (' + historyCount + ' entries)</div>';
                    previewHtml += '<div class="text-sub" style="font-size:12px">Full workout history will be imported</div>';
                }
                previewHtml += '</div>';

                $('sync-content').innerHTML = `
                <div class="sync-hero">
                    <span class="status-icon"><svg class="icon icon-xxl" viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg></span>
                    <h2 class="mb-2">Data Received!</h2>
                    <span class="sync-pill ${isEncrypted ? 'encrypted' : 'simple'}">${isEncrypted ? '<svg class="icon icon-sm" viewBox="0 0 24 24" style="vertical-align:-3px"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Decrypted Successfully' : '<svg class="icon icon-sm" viewBox="0 0 24 24" style="vertical-align:-3px"><path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8M16 6l-4-4-4 4M12 2v13"/></svg> Simple Transfer'}</span>
                    <p class="text-sub" style="margin-top:12px">Review the incoming data before importing:</p>
                </div>
                ${previewHtml}
                <div style="padding: 0 16px;">
                    ${isEncrypted ? `
                    <button class="btn-primary w-100 mb-2" onclick="SyncUI._confirmImport('full')" style="padding:18px; display:flex; align-items:center; justify-content:center; gap:8px">
                        <svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke:#fff"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg> Full Sync (Replace Everything)
                    </button>
                    <button class="btn-panel w-100 mb-4" onclick="SyncUI._confirmImport('merge')" style="display:flex; align-items:center; justify-content:center; gap:8px">
                        <svg class="icon icon-sm" viewBox="0 0 24 24"><path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/></svg> Merge (Add routines, keep existing)
                    </button>` : `
                    <button class="btn-primary w-100 mb-2" onclick="SyncUI._confirmImport('merge')" style="background:var(--green); padding:18px; display:flex; align-items:center; justify-content:center; gap:8px">
                        <svg class="icon icon-sm" viewBox="0 0 24 24" style="stroke:#fff"><path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/></svg> Add Routines to My Collection
                    </button>`}
                    <button class="btn-panel w-100 text-sub" onclick="SyncUI._rejectImport()">Cancel Import</button>
                </div>`;

                this._pendingData = data;
                this._pendingEncrypted = isEncrypted;
            },

            async _confirmImport(strategy) {
                const data = this._pendingData;
                if (!data) return;
                if (!Store.data || !Array.isArray(Store.data.routines) || !Array.isArray(Store.data.history)) {
                    Sys.toast('Local data is corrupted — aborting import');
                    return;
                }

                try {
                    if (strategy === 'full') {
                        
                        Store.data = {
                            routines: Array.isArray(data.routines) ? data.routines : [],
                            history: Array.isArray(data.history) ? data.history : [],
                            lastId: data.lastId || null
                        };
                    } else {
                        
                        const existingIds = new Set(Store.data.routines.map(r => r.id));
                        if (Array.isArray(data.routines)) {
                            data.routines.forEach(r => {
                                if (!r || !r.id) return;
                                if (!existingIds.has(r.id)) {
                                    Store.data.routines.push(r);
                                } else {
                                    
                                    r.id = uuid();
                                    Store.data.routines.push(r);
                                }
                            });
                        }
                        
                        if (Array.isArray(data.history)) {
                            const existHist = new Set(Store.data.history.map(h => h.id));
                            data.history.forEach(h => {
                                if (!h || !h.id) return;
                                if (!existHist.has(h.id)) Store.data.history.push(h);
                            });
                            Store.data.history.sort((a, b) => (b.d || 0) - (a.d || 0));
                        }
                    }

                    await Store.save();
                    Peer.send(JSON.stringify({ t: 'ack' }));

                    this._pendingData = null;
                    this._pendingEncrypted = null;
                    this._renderComplete('receive');
                } catch (e) {
                    console.error('_confirmImport failed:', e);
                    Sys.toast('Import failed — please try again');
                    try { Peer.send(JSON.stringify({ t: 'err', msg: 'Import failed: ' + (e.message || 'unknown') })); } catch (_) {}
                }
            },

            _rejectImport() {
                try { Peer.send(JSON.stringify({ t: 'err', msg: 'Receiver rejected the import' })); } catch (_) {}
                Peer.reset();
                this._pendingData = null;
                this._pendingEncrypted = null;
                this._renderStatus('<svg class="icon icon-lg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>', 'Import Cancelled', 'You cancelled the data import. No changes were made.');
            },

            
            _renderStatus(icon, title, desc, showSpinner = false) {
                const sc = $('sync-content');
                if (!sc) return;
                sc.innerHTML = `
                <div class="sync-status" style="padding-top: 80px;">
                    <span class="status-icon ${showSpinner ? 'pulse-ring' : ''}">${icon}</span>
                    <h2 class="mb-4">${Sys.escapeHTML(title)}</h2>
                    <p class="text-sub" style="line-height:1.5; padding: 0 16px;">${Sys.escapeHTML(desc)}</p>
                    ${showSpinner ? '<div class="sync-progress" style="margin:24px 16px;"><div class="sync-progress-bar" style="width:60%; animation: pulseRing 2s infinite;"></div></div>' : ''}
                    ${!showSpinner ? '<div style="padding:24px 16px;"><button class="btn-panel w-100" onclick="SyncUI.open()">← Try Again</button></div>' : ''}
                </div>`;
            },

            _renderComplete(role) {
                Sys.vibrate([30, 50, 30]);

                const isEnc = this.mode === 'encrypted';
                const sc = $('sync-content');
                if (!sc) return;
                sc.innerHTML = `
                <div class="sync-status" style="padding-top: 60px;">
                    <span class="status-icon" style="font-size:72px"><svg class="icon" viewBox="0 0 24 24" style="width:72px;height:72px;stroke:var(--green)"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></span>
                    <h1 class="mb-4" style="color:var(--green)">Sync Complete!</h1>
                    <span class="sync-pill ${isEnc ? 'encrypted' : 'simple'}">${isEnc ? '<svg class="icon icon-sm" viewBox="0 0 24 24" style="vertical-align:-3px"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> Encrypted Transfer' : '<svg class="icon icon-sm" viewBox="0 0 24 24" style="vertical-align:-3px"><path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8M16 6l-4-4-4 4M12 2v13"/></svg> Simple Transfer'}</span>
                    <p class="text-sub" style="margin-top:16px; line-height:1.5; padding: 0 16px;">
                        ${role === 'send'
                        ? 'Your data was successfully sent and accepted by the receiving device.'
                        : 'Data has been imported to your vault successfully!'}
                    </p>
                    <div style="padding:32px 16px;">
                        <button class="btn-primary w-100" onclick="SyncUI.close(); Peer.reset();">Done</button>
                    </div>
                </div>`;
            },

            _copyToClip(elId) {
                const el = $(elId);
                const text = el && el.innerText;
                if (!text) return;
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text)
                        .then(() => Sys.toast('Copied to clipboard!'))
                        .catch(() => this._copyFallback(text));
                } else {
                    this._copyFallback(text);
                }
            },
            _copyFallback(text) {
                try {
                    const ta = document.createElement('textarea'); ta.value = text;
                    ta.style.position = 'fixed'; ta.style.left = '-9999px';
                    document.body.appendChild(ta); ta.select();
                    const ok = document.execCommand && document.execCommand('copy');
                    document.body.removeChild(ta);
                    Sys.toast(ok ? 'Copied!' : 'Copy not supported');
                } catch (e) {
                    Sys.toast('Copy not supported');
                }
            },

            _escapeHtml(str) {
                const d = document.createElement('div');
                d.textContent = str;
                return d.innerHTML;
            }
        };

        
        
        function bootstrap() {
            try { Settings.bind(); } catch (e) { console.error('Settings.bind failed:', e); }
            try { Auth.init(); } catch (e) { console.error('Auth.init failed:', e); }
            document.addEventListener('visibilitychange', () => {
                
                
                const vActive = $('v-active');
                if (document.visibilityState === 'visible' && vActive && !vActive.classList.contains('hidden')) {
                    Sys.wakeLock();
                }
            });
            
            window.addEventListener('unhandledrejection', e => {
                console.error('Unhandled promise rejection:', e.reason);
            });
            window.addEventListener('error', e => {
                console.error('Unhandled error:', e.error || e.message);
            });
        }
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', bootstrap);
        } else {
            bootstrap();
        }

        
        
        try {
            const mfest = {
                name: "VaultFit Pro", short_name: "VaultFit", start_url: location.href, display: "standalone",
                background_color: "#0f0f0f", theme_color: "#C8C8CC",
                icons: [{ "src": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='50' fill='%23C8C8CC'/><text x='50' y='65' fill='white' font-family='sans-serif' font-size='40' font-weight='800' text-anchor='middle'>VF</text></svg>", "sizes": "512x512", "type": "image/svg+xml" }]
            };
            const mL = document.createElement('link'); mL.rel = 'manifest';
            mL.href = 'data:application/manifest+json,' + encodeURIComponent(JSON.stringify(mfest));
            document.head.appendChild(mL);
        } catch (e) {
            console.warn('PWA manifest setup skipped:', e);
        }

        
        
        
        
        
