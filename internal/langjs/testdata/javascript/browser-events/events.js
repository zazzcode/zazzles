const input = document.querySelector('input');
function raw(event) {
  document.body.innerHTML = event.target.value;
}
input.addEventListener('input', raw);
input.addEventListener('change', raw);
document.addEventListener('submit', (event) => {
  document.body.textContent = event.target.value;
});
window.addEventListener('message', (event) => {
  document.body.innerHTML = wrap(event.data);
});
window.addEventListener('click', () => {});
window.addEventListener('message', missingCallback);
