const input = document.querySelector('input');
function raw(event: Event) {
  document.body.innerHTML = event.target.value;
}
input.addEventListener('input', raw);
input.addEventListener('change', raw);
document.addEventListener('submit', (event: Event) => {
  document.body.textContent = event.target.value;
});
window.addEventListener('message', (event: MessageEvent) => {
  document.body.innerHTML = wrap(event.data);
});
window.addEventListener('click', () => {});
window.addEventListener('message', missingCallback);
