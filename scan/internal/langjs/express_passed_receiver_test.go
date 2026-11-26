package langjs

import (
	"strings"
	"testing"
)

// TestExpressAppPassedToAnotherModule reads routes registered on an Express app
// that the server file passes to a function of another module, with handlers and
// middleware that are methods of constructed objects, and follows a database
// handle through constructor functions and a connect callback.
func TestExpressAppPassedToAnotherModule(t *testing.T) {
	files := map[string]string{
		"package.json": `{"dependencies":{"express":"4.18.0","mongodb":"2.2.36"}}`,
		"server.js": `const express = require("express");
const MongoClient = require("mongodb").MongoClient;
const routes = require("./routes");
const app = express();
MongoClient.connect("mongodb://x", (err, db) => {
    app.use(express.json());
    routes(app, db);
    app.listen(3000);
});
`,
		"routes/index.js": `const Items = require("./items");
const index = (app, db) => {
    const items = new Items(db);
    const signedIn = items.signedIn;
    app.post("/items", signedIn, items.search);
    app.get("/things/:id", items.byThreshold);
};
module.exports = index;
`,
		"routes/items.js": `const ItemsDAO = require("../data/items-dao").ItemsDAO;
function Items(db) {
    const dao = new ItemsDAO(db);
    this.signedIn = (req, res, next) => req.session ? next() : res.redirect("/login");
    this.search = (req, res, next) => {
        const { name } = req.body;
        dao.byName(name, (err, item) => res.json(item));
    };
    this.byThreshold = (req, res, next) => {
        dao.above(req.query.threshold, (err, rows) => res.json(rows));
    };
}
module.exports = Items;
`,
		"data/items-dao.js": `function ItemsDAO(db) {
    const col = db.collection("items");
    this.byName = (name, callback) => {
        col.findOne({ name: name }, callback);
    };
    this.above = (threshold, callback) => {
        const criteria = () => ({ $where: ` + "`this.stock > '${threshold}'`" + ` });
        col.find(criteria()).toArray(callback);
    };
}
module.exports = { ItemsDAO };
`,
	}
	root := t.TempDir()
	for name, text := range files {
		writeSource(t, root, name, text)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct{ entry, sink string }{{"POST /items", "col.findOne({ name: name }, callback)"}, {"GET /things/:id", "col.find(criteria())"}} {
		found := false
		for _, u := range r.Uses {
			if u.Kind != "nosql_query_candidate" || u.Sink.Text != want.sink {
				continue
			}
			found = true
			for _, e := range r.Entries {
				if e.ID == u.EntryID && e.Name != want.entry {
					t.Errorf("%s recorded on %s", want.sink, e.Name)
				}
			}
			path := u.Completeness.Evidence["sink_binding"]
			if u.APIModel == nil || u.APIModel.ID != "mongodb-document-query-v1" || len(path) < 3 || !strings.Contains(path[0].Text, `require("mongodb")`) {
				t.Errorf("%s: no receiver path from the mongodb import", want.sink)
			}
			if len(u.Completeness.Blockers) != 0 {
				t.Errorf("%s is held by %v", want.sink, u.Completeness.Blockers)
			}
		}
		if !found {
			names := []string{}
			for _, e := range r.Entries {
				names = append(names, e.Name)
			}
			t.Errorf("no record at %q; entries %v", want.sink, names)
		}
	}
	// A function that is passed something other than the app registers nothing.
	files["server.js"] = strings.Replace(files["server.js"], "routes(app, db)", "routes({ post() {}, get() {} }, db)", 1)
	root = t.TempDir()
	for name, text := range files {
		writeSource(t, root, name, text)
	}
	if r, err = Analyze(root, ""); err != nil {
		t.Fatal(err)
	}
	for _, e := range r.Entries {
		if strings.Contains(e.Name, "/items") || strings.Contains(e.Name, "/things") {
			t.Errorf("entry %s on a parameter that is not an Express app", e.Name)
		}
	}
}
