// D1-I5D.1b internal storage primitive. Not an admission authority.
// Only a trusted adapter may select a namespace; never expose store callbacks to UI.
export function createAdmissionStore(DB) {
  if(typeof DB!=='string'||!/^iamina-d1-admission-[a-z0-9-]+$/.test(DB))throw new Error('Invalid admission namespace');
  const STORE='state';
  const require=(ok,message)=>{if(!ok)throw new Error(message);};
  async function connect() {
    require(isSecureContext&&globalThis.indexedDB&&globalThis.crypto?.subtle,'Secure storage unavailable');
    return new Promise((resolve,reject)=>{
      const r=indexedDB.open(DB,1);
      r.onupgradeneeded=()=>r.result.createObjectStore(STORE);
      let blocked=false;
      r.onsuccess=()=>{const db=r.result;if(blocked){db.close();return;}db.onversionchange=()=>db.close();resolve(db);};
      r.onerror=()=>reject(new Error('Admission store unavailable'));
      r.onblocked=()=>{blocked=true;reject(new Error('Admission store blocked'));};
    });
  }
  // Read owner and global fence in one transaction. Callback must be synchronous.
  // Writes and the fence check share one strict readwrite transaction.
  async function transaction(owner,write,fn) {
    const db=await connect();
    try{
      return await new Promise((resolve,reject)=>{
        const tx=write?db.transaction(STORE,'readwrite',{durability:'strict'}):
          db.transaction(STORE,'readonly');
        let result, failure;
        tx.oncomplete=()=>resolve(result);
        tx.onabort=()=>reject(failure||new Error('Admission transaction failed'));
        if(write&&tx.durability!=='strict'){
          failure=new Error('Strict durability unavailable');tx.abort();return;
        }
        const store=tx.objectStore(STORE);
        const ownerReq=store.get('owner:'+owner), fenceReq=store.get('fence');
        let ready=0;
        const done=()=>{
          if(++ready!==2)return;
          try{
            result=fn(ownerReq.result??null,fenceReq.result??null,store);
          }catch(e){failure=e;tx.abort();}
        };
        ownerReq.onsuccess=done;fenceReq.onsuccess=done;
      });
    }finally{db.close();}
  }
  async function readFence(){
    const db=await connect();
    try{
      return await new Promise((resolve,reject)=>{
        const tx=db.transaction(STORE,'readonly');
        const request=tx.objectStore(STORE).get('fence');
        tx.oncomplete=()=>resolve(request.result??null);
        tx.onabort=()=>reject(new Error('Admission fence unavailable'));
      });
    }finally{db.close();}
  }
  return Object.freeze({transaction,readFence});
}
