function readItem() {
  return true
}

app.route('/api/items/:id')
  .get(readItem())
  .put(writeItem)
  .delete(removeItem)

app.route(itemPath).get(readItem)
