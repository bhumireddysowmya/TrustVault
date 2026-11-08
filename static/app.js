let token = null, me = null, privateKey = null;
const $ = s => document.querySelector(s), te = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const pemDer = s => unb64(s.replace(/-----[^-]+-----/g, "").replace(/\s/g, ""));
async function derive(pw, salt) {
  const base = await crypto.subtle.importKey("raw", te.encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt, iterations:250000, hash:"SHA-256"}, base,
    {name:"AES-GCM", length:256}, false, ["encrypt", "decrypt"]);
}
async function makeKeys(pw) {
  const pair = await crypto.subtle.generateKey({name:"RSA-OAEP", modulusLength:2048,
    publicExponent:new Uint8Array([1,0,1]), hash:"SHA-256"}, true, ["encrypt", "decrypt"]);
  const pub = await crypto.subtle.exportKey("spki", pair.publicKey), priv = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12)), k = await derive(pw, salt);
  const cipher = await crypto.subtle.encrypt({name:"AES-GCM", iv}, k, priv);
  return {public_key:"-----BEGIN PUBLIC KEY-----\n"+b64(pub)+"\n-----END PUBLIC KEY-----",
    private_key_bundle:JSON.stringify({salt:b64(salt), iv:b64(iv), cipher:b64(cipher)}), privateKey:pair.privateKey};
}
async function unlock(bundle, pw) {
  const x = JSON.parse(bundle), k = await derive(pw, unb64(x.salt));
  const raw = await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(x.iv)}, k, unb64(x.cipher));
  return crypto.subtle.importKey("pkcs8", raw, {name:"RSA-OAEP", hash:"SHA-256"}, false, ["decrypt"]);
}
async function pubkey(p) { return crypto.subtle.importKey("spki", pemDer(p), {name:"RSA-OAEP", hash:"SHA-256"}, false, ["encrypt"]); }
async function wrap(raw, p) { return b64(await crypto.subtle.encrypt({name:"RSA-OAEP"}, await pubkey(p), raw)); }
async function unwrap(s) { return crypto.subtle.decrypt({name:"RSA-OAEP"}, privateKey, unb64(s)); }
async function api(path, opt={}) {
  const r = await fetch("/api"+path, {...opt, headers:{...(opt.headers||{}), ...(token?{Authorization:"Bearer "+token}:{})}});
  let d; try { d = await r.json(); } catch { d = {detail:"Server error"}; }
  if (!r.ok) throw Error(d.detail || "Request failed"); return d;
}
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function showAuth(m) { $("#auth-msg").textContent = m; }
function message(m) {
  $("#notice-text").textContent = m;
  $("#notice").classList.remove("hide");
}

$("#notice-ok").onclick = () => {
  $("#notice").classList.add("hide");
};

document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
  document.querySelectorAll("nav button").forEach(x => x.classList.remove("selected")); b.classList.add("selected");
  $("#login").classList.toggle("hide", b.id !== "login-tab"); $("#register").classList.toggle("hide", b.id !== "reg-tab"); showAuth("");
});
$("#register").onsubmit = async e => {
  e.preventDefault(); const f = new FormData(e.target), pw = f.get("password");
  try { showAuth("Creating browser encryption keys…"); const k = await makeKeys(pw);
    const d = await api("/register", {method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({name:f.get("name"), email:f.get("email"), password:pw, public_key:k.public_key, private_key_bundle:k.private_key_bundle})});
    token=d.token; me=d.user; privateKey=k.privateKey; await enter();
  } catch(x) { showAuth(x.message); }
};
$("#login").onsubmit = async e => {
  e.preventDefault(); const f = new FormData(e.target), pw = f.get("password");
  try { showAuth("Unlocking your private key…"); const d = await api("/login", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({email:f.get("email"), password:pw})});
    token=d.token; me=d.user; privateKey=await unlock(me.private_key_bundle,pw); await enter();
  } catch(x) { showAuth(x.message); }
};
async function enter() {
  $("#auth").classList.add("hide"); $("#workspace").classList.remove("hide"); $("#who").textContent =
    me.name + " · " + (me.role || "user" ).toUpperCase();
  $("#admin-panel")?.classList.toggle("hide", me.role !== "admin"); $("#verify")?.classList.toggle("hide", me.role !== "admin"); $("#upload-label")?.classList.toggle("hide", me.role === "viewer"); $("#category-label")?.classList.toggle("hide", me.role === "viewer"); if(me.role!=="admin"){ $("#audit-state").textContent="Restricted"; $("#audit-detail").textContent="Administrator verification only"; } await refresh();
}
$("#logout").onclick = () => { token=null; me=null; privateKey=null; $("#workspace").classList.add("hide"); $("#auth").classList.remove("hide"); $("#who").textContent=""; };
$("#file").onchange = async e => {
  const f = e.target.files[0];
  if (!f) return;

  if (f.size === 0) {
    alert("Empty files cannot be uploaded. Please select a file with content.");
    e.target.value = "";
    return;
  }
  try { message("Encrypting in your browser…"); const raw=crypto.getRandomValues(new Uint8Array(32));
    const key=await crypto.subtle.importKey("raw",raw,{name:"AES-GCM"},false,["encrypt"]), iv=crypto.getRandomValues(new Uint8Array(12));
    const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,await f.arrayBuffer()), packed=new Uint8Array(12+cipher.byteLength);
    packed.set(iv); packed.set(new Uint8Array(cipher),12); const fd=new FormData(); fd.append("file",new Blob([packed]),f.name);
    fd.append("wrapped_key",await wrap(raw,me.public_key)); fd.append("category",$("#category")?.value || "General");
    await api("/documents",{method:"POST",body:fd}); message("Encrypted and uploaded successfully."); await refresh();
  } catch(x) { message(x.message); } finally { e.target.value=""; }
};
function searchParams() {
  const p=new URLSearchParams();
  for(const [id,key] of [["search-name","name"],["search-owner","owner"],["search-category","category"],["search-from","date_from"],["search-to","date_to"]]) {
    const v=$("#"+id)?.value?.trim(); if(v)p.set(key,v);
  }
  return p.toString()?"?"+p.toString():"";
}
async function refresh() {
  const docs=await api("/documents"+searchParams()); $("#count").textContent=docs.length;
  $("#docs").innerHTML=docs.length?docs.map(d=>`<div class="doc"><div class="ico">▤</div>
<div class="name">
  <b>${esc(d.filename)}</b>
  <small>
    ${d.owner? "OWNER" : esc(d.permission.toUpperCase()) + " · SHARED"}
    · ${esc(d.category)}
    · ${new Date(
      d.created_at.endsWith("Z") || /[+-]\d{2}:\d{2}$/.test(d.created_at)
        ? d.created_at
        : d.created_at + "Z"
    ).toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour12: false
    })}
  </small>
</div>
<button class="mini" data-open="${d.id}">Open</button>${d.owner||d.permission==="edit"?`<button class="mini" data-edit="${d.id}">Edit details</button>`:""}${d.owner
  ? `<button class="mini" data-share="${d.id}">Share</button>
     <button class="mini" data-permissions="${d.id}">People</button>
     <button class="mini" data-delete="${d.id}">Delete</button>`
  : me.role === "admin"
    ? `<button class="mini" data-permissions="${d.id}">People</button>`
    : ""}</div>`).join("") : "<p class='hint'>No documents found.</p>";
  $("#docs").querySelectorAll("[data-open]").forEach(b=>b.onclick=()=>openDoc(b.dataset.open));
  $("#docs").querySelectorAll("[data-share]").forEach(b=>b.onclick=()=>share(b.dataset.share));
  $("#docs").querySelectorAll("[data-edit]").forEach(b=>b.onclick=()=>editDoc(b.dataset.edit));
  $("#docs").querySelectorAll("[data-delete]").forEach(b=>b.onclick=()=>deleteDoc(b.dataset.delete));
  $("#docs").querySelectorAll("[data-permissions]").forEach(b=>b.onclick=()=>managePermissions(b.dataset.permissions));
  await loadEvents(); if(me.role==="admin")await verify();
}
async function openDoc(id) {
  try { message("Checking permission…"); const m=await api(`/documents/${id}/key`);
    const r=await fetch(`/api/documents/${id}/ciphertext`,{headers:{Authorization:"Bearer "+token}}); if(!r.ok)throw Error("Unable to retrieve encrypted file");
    const data=new Uint8Array(await r.arrayBuffer()), raw=await unwrap(m.wrapped_key), key=await crypto.subtle.importKey("raw",raw,{name:"AES-GCM"},false,["decrypt"]);
    const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:data.slice(0,12)},key,data.slice(12)), url=URL.createObjectURL(new Blob([plain],{type:m.mime_type}));
    $("#modal-title").textContent=m.filename; $("#modal-content").innerHTML=`<p class="hint">Decrypted locally in your browser. The server stores ciphertext only.</p><a id="download" class="primary" download="${esc(m.filename)}">Download decrypted file</a>`;
    $("#download").href=url; $("#modal").classList.remove("hide"); message("Document decrypted successfully.");
  } catch(x) { message(x.message); }
}
async function share(id) {
  $("#modal-title").textContent="Share document";
  $("#modal-content").innerHTML='<p class="hint">The recipient must already have a TrustVault account.</p><label>Recipient email<input id="recipient" type="email" placeholder="person@example.com"></label><label>Permission<select id="grant-level"><option value="read">Read</option><option value="edit">Edit</option></select></label><button id="grant" class="primary">Grant access</button><p id="share-msg"></p>';
  $("#modal").classList.remove("hide"); $("#grant").onclick=async()=>{try{const email=$("#recipient").value.trim().toLowerCase(), recipient=await api("/lookup?email="+encodeURIComponent(email)), doc=await api(`/documents/${id}/key`), raw=await unwrap(doc.wrapped_key), wrapped_key=await wrap(raw,recipient.public_key);
    const res=await api(`/documents/${id}/share`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,wrapped_key,permission:$("#grant-level").value})}); $("#share-msg").textContent=res.message; await refresh();
  }catch(x){$("#share-msg").textContent=x.message;}};
}
async function managePermissions(id) {
  try {const rows=await api(`/documents/${id}/permissions`); $("#modal-title").textContent="Document access";
    $("#modal-content").innerHTML=rows.map(p=>`<div class="event"><b>${esc(p.name)} · ${esc(p.permission)}</b><small>${esc(p.email)}</small>${p.permission!=="owner"?`<button class="mini" data-revoke="${p.user_id}">Revoke</button>`:""}</div>`).join("")||"<p>No grants.</p>";
    $("#modal").classList.remove("hide"); $("#modal-content").querySelectorAll("[data-revoke]").forEach(b=>b.onclick=async()=>{try{await api(`/documents/${id}/permissions/${b.dataset.revoke}`,{method:"DELETE"}); await managePermissions(id); await refresh();}catch(x){alert(x.message);}});
  }catch(x){message(x.message);}
}
async function editDoc(id) {
  const d=(await api("/documents" )).find(x=>x.id===id); if(!d)return;
  $("#modal-title").textContent="Edit document details";
  $("#modal-content").innerHTML=`<label>File name<input id="edit-name" value="${esc(d.filename)}"></label><label>Category<input id="edit-category" value="${esc(d.category)}"></label><button id="save-edit" class="primary">Save changes</button><p id="edit-msg"></p>`;
  $("#modal").classList.remove("hide"); $("#save-edit").onclick=async()=>{try{await api(`/documents/${id}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({filename:$("#edit-name").value,category:$("#edit-category").value})}); $("#edit-msg").textContent="Saved"; await refresh();}catch(x){$("#edit-msg").textContent=x.message;}};
}
async function deleteDoc(id) { if(!confirm("Permanently delete this document and its encrypted server copy?"))return; try{await api(`/documents/${id}`,{method:"DELETE"});message("Document deleted.");await refresh();}catch(x){message(x.message);} }
$("#close").onclick=()=>$("#modal").classList.add("hide"); $("#modal").onclick=e=>{if(e.target.id==="modal")$("#modal").classList.add("hide");};
async function loadEvents() {
    const d = await api("/audit");

    $("#events").innerHTML = d.events.length
        ? d.events.slice(0, 12).map(x => {
            let actionName = x.action.replaceAll("_", " ");
            const permission = x.details?.permission;

            if (x.action === "DOCUMENT_KEY_GRANTED") {
                actionName = permission
                    ? `${permission.charAt(0).toUpperCase() + permission.slice(1)} key granted`
                    : "Document key granted";
            }

            if (x.action === "PERMISSION_GRANTED") {
                actionName = permission
                    ? `${permission.charAt(0).toUpperCase() + permission.slice(1)} permission granted`
                    : "Permission granted";
            }

            if (x.action === "PERMISSION_REVOKED") {
                actionName = permission
                    ? `${permission.charAt(0).toUpperCase() + permission.slice(1)} permission revoked`
                    : "Permission revoked";
            }

            const timestamp = x.timestamp +
                (/[zZ]|[+-]\d{2}:\d{2}$/.test(x.timestamp) ? "" : "Z");
            const actor = x.details?.actor_snapshot;
            const actorLabel = x.actor_id === me.id
              ? "YOU"
              : actor
                  ? `${esc(actor.name)} (${esc(actor.email)})`
                  : "ACCOUNT " + x.actor_id;
            return `
                <div class="event">
                    <b>${esc(actionName)}</b>
                    <small>
                        ${new Date(timestamp).toLocaleString("en-IN", {
                            timeZone: "Asia/Kolkata",
                            hour12: false
                        })}
                        · ${actorLabel}
                    </small>
                </div>
            `;
        }).join("")
        : "<p class='hint'>No events yet.</p>";
}
async function verify() {const d=await api("/audit/verify"); $("#audit-state").textContent=d.valid?"Valid":"Alert"; $("#audit-detail").textContent=d.valid?`${d.checked} events verified`:`Tampering at event ${d.failed_event}`;}
$("#verify").onclick=async()=>{try{await verify();$("#verify-msg").textContent=$("#audit-state").textContent+" — "+$("#audit-detail").textContent;}catch(x){$("#verify-msg").textContent=x.message;}};
$("#search-button")?.addEventListener("click",()=>refresh());
$("#clear-search")?.addEventListener("click",()=>{document.querySelectorAll(".search-fields input").forEach(x=>x.value="");refresh();});

$("#admin-refresh")?.addEventListener("click", async () => {
    try {
        const d = await api("/admin/activity");

        const users = await api("/admin/users");

        const getUser = (id) => users.find(user => user.id === id);

        const actionNames = {
            "LOGIN_SUCCESS": "User logged in",
            "USER_ROLE_CHANGED": "User role changed",
            "ADMIN_BOOTSTRAPPED": "Administrator configured",
            "ADMIN_ACTION_DENIED": "Admin action denied",
            "ACCESS_DENIED": "Document access denied",
            "DOCUMENT_UPLOADED": "Document uploaded",
            "DOCUMENT_OPENED": "Document opened",
            "DOCUMENT_SHARED": "Document shared",
            "DOCUMENT_REVOKED": "Document access revoked"
        };

        $("#admin-events").innerHTML = d.events.map(e => {
            const details = e.details || {};

            const actor = details.actor_snapshot;
            const target = details.target_user_snapshot;
            const targetUser = target || getUser(Number(details.target_user_id));
            const document = details.document_snapshot;

            const oldActor = getUser(e.actor_id);

            const actorName = actor
                ? `${actor.name} (${actor.email})`
                : oldActor
                    ? `${oldActor.name} (${oldActor.email})`
                    : `User ID ${e.actor_id ?? "Unknown"}`;

            let extra = "";

            if (e.action === "USER_ROLE_CHANGED") {
                extra = `
                    <p>
                        <b>Person affected:</b>
                        ${targetUser
                          ? `${esc(targetUser.name)} (${esc(targetUser.email)})`
                          : `User ID ${esc(details.target_user_id ?? "Unknown")}`}
                        <br>
                        <b>Role changed:</b>
                        ${esc(details.old_role ?? "Unknown")}
                        → ${esc(details.new_role ?? "Unknown")}
                    </p>
                `;
            }

            return `
                <div class="event">
                    <b>${esc(actionNames[e.action] || e.action)}</b>
                    <small>
                        <b>Performed by:</b> ${esc(actorName)}<br>
                        <b>Document:</b> ${esc(document?.filename || e.document_id || "Account activity")}<br>
                        <b>Date:</b> 
                        ${new Date(
                         e.timestamp.endsWith("Z") || /[+-]\d{2}:\d{2}$/.test(e.timestamp)
                            ? e.timestamp
                            : e.timestamp + "Z"
                        ).toLocaleString("en-IN", {
                          timeZone: "Asia/Kolkata",
                          hour12: false
                        })}
                    </small>
                    ${extra}
                </div>
            `;
        }).join("") || "<p>No activity.</p>";

    } catch (error) {
        $("#admin-events").textContent = error.message;
    }
});

$("#users-refresh")?.addEventListener("click", loadAdminUsers);

async function loadAdminUsers() {
    const container = $("#admin-users");

    try {
        container.textContent = "Loading users...";

        const users = await api("/admin/users");

        container.innerHTML = users.map(user => `
            <div class="event">
                <b>${esc(user.name)}</b>
                <small>${esc(user.email)}</small>

                <label>
                    Role:
                    <select data-role-user="${user.id}">
                        <option value="owner" ${user.role === "owner" ? "selected" : ""}>Owner</option>
                        <option value="viewer" ${user.role === "viewer" ? "selected" : ""}>Viewer</option>
                        <option value="admin" ${user.role === "admin" ? "selected" : ""}>Admin</option>
                    </select>
                </label>

                <button class="mini" data-save-role="${user.id}">
                    Update Role
                </button>
            </div>
        `).join("") || "<p>No registered users found.</p>";

        container.querySelectorAll("[data-save-role]").forEach(button => {
            button.addEventListener("click", async () => {
                const userId = button.dataset.saveRole;
                const role = container.querySelector(
                    `[data-role-user="${userId}"]`
                ).value;

                if (!confirm(`Change this user's role to ${role}?`)) return;

                try {
                    await api(`/admin/users/${userId}/role`, {
                        method: "PATCH",
                        headers: {"Content-Type": "application/json"},
                        body: JSON.stringify({role})
                    });

                    alert("User role updated successfully.");
                    await loadAdminUsers();

                } catch (error) {
                    alert(error.message);
                }
            });
        });

    } catch (error) {
        container.textContent = error.message;
    }
}