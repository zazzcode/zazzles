fetch('/item', {method: 'POST'}).then(r => r.json()).then(r => {
  document.getElementById('out').innerHTML = r.name;
});
