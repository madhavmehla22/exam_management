document.addEventListener('submit',e=>{const m=e.target.dataset.confirm;if(m&&!confirm(m))e.preventDefault();
const b=e.target.querySelector('button:not([type=button])');if(b&&!e.defaultPrevented){b.disabled=true;b.insertAdjacentHTML('afterbegin','<span class="spinner-border spinner-border-sm me-1"></span>')}});
