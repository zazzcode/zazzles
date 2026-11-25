package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

var sqlContractIDs = []string{"sequelize-raw-query-v1", "sqljs-statement-v1", "python-sqlite3-dbapi-v1", "python-psycopg-dbapi-v1", "python-psycopg2-dbapi-v1", "python-pymysql-dbapi-v1", "python-mysql.connector-dbapi-v1", "php-mysqli-v1", "php-pdo-v1", "php-sqlite3-v1", PHPDoctrineDBALContract, PHPDoctrineORMContract, SequelizeFinderContract, PrismaRawContract, BetterSQLite3Contract, PGliteContract, PackageSQLContract}

const (
	PHPDoctrineDBALContract = "php-doctrine-dbal-v1"
	PHPDoctrineORMContract  = "php-doctrine-orm-v1"
)

// PrismaRawContract is Prisma Client's unsafe raw-SQL API.
const PrismaRawContract = "prisma-raw-v1"

// BetterSQLite3Contract is the better-sqlite3 Database statement API.
const BetterSQLite3Contract = "better-sqlite3-v1"

// PGliteContract is the PGlite (embedded Postgres) query API.
const PGliteContract = "pglite-v1"

// PackageSQLContract is a call on a third-party package value the scanner has no
// written contract for. It states no behavior: the model says what the callee
// does with its argument and the record stays unverified until that answer's
// citation verifies.
const PackageSQLContract = "package-sql-call-v1"

// SequelizeFinderContract is a Sequelize model finder whose where values are bound.
const SequelizeFinderContract = "sequelize-model-finder-v1"

// SQLContract returns a copy of the supported operation contract by verified model ID.
func SQLContract(id string) *analysis.APIModel {
	if id == "sequelize-raw-query-v1" {
		return &analysis.APIModel{ID: "sequelize-raw-query-v1", Library: "sequelize", Semantics: "Sequelize query takes executable SQL text as its first argument. bind and replacements supply separated data values according to their API. model, plain and result-format options do not parameterize an already-interpolated SQL string.", Reference: "https://sequelize.org/docs/v6/core-concepts/raw-queries/"}
	}
	if id == SequelizeFinderContract {
		return &analysis.APIModel{ID: id, Library: "sequelize", Reference: "https://sequelize.org/docs/v6/core-concepts/model-querying-basics/#operators",
			Semantics: "Model.findAll, findOne, findAndCountAll, count and findOrCreate build SQL from a where object; attribute values and operator operands such as Op.like, Op.eq and Op.in are sent as escaped or bound values, so request text in them cannot change SQL syntax. Inside an Op.like (or Op.iLike, Op.notLike) operand the characters % and _ are LIKE wildcards: an unescaped request value can widen the match, which is an input-validation and resource concern, not SQL injection. Raw SQL fragments (Sequelize.literal, sequelize.literal, Op.literal or a literal attribute/order string) are not bound and are outside this contract. Attribute names, order and group keys taken from a request are not values."}
	}
	if id == PrismaRawContract {
		return &analysis.APIModel{ID: id, Library: "prisma", Reference: "https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries",
			Semantics: "$queryRawUnsafe(sql, ...values) and $executeRawUnsafe(sql, ...values) send their first argument as executable SQL text; values after it are bound to positional placeholders ($1, ?) and cannot protect SQL already interpolated into the text. The tagged-template forms $queryRaw`...${v}` and $executeRaw`...` bind every substitution as a parameter, except fragments built with Prisma.raw, which are raw SQL. Model methods such as findMany, findUnique and update are parameterized and outside this contract."}
	}
	if id == BetterSQLite3Contract {
		return &analysis.APIModel{ID: id, Library: "better-sqlite3", Reference: "https://github.com/WiseLibs/better-sqlite3/blob/master/docs/api.md",
			Semantics: "Database.exec(sql) runs every statement in its SQL text argument and binds nothing (sql_multi_statement). Database.prepare(sql) compiles exactly one statement from its first argument and refuses multiple statements (sql_single_statement); values passed to the statement's run, get, all or iterate are bound to ?, @name, :name or $name placeholders and cannot protect SQL already interpolated into the prepared text. pragma(text) runs its argument as SQL like exec."}
	}
	if id == PackageSQLContract {
		return &analysis.APIModel{ID: id, Library: "package", Reference: "https://cwe.mitre.org/data/definitions/89.html",
			Semantics: "The scanner has no written contract for this imported package. It established only that a string built from request data, whose constant text begins a SQL statement, is passed to this call and that the callee's value starts at the cited import. What the call does with that argument is asked in resolve_sqlcall. Answer injection_protection for the operation as you answer it there; the scanner discards both unless the citation verifies."}
	}
	if id == PGliteContract {
		return &analysis.APIModel{ID: id, Library: "pglite", Reference: "https://pglite.dev/docs/api",
			Semantics: "PGlite.query(sql, params) runs exactly one statement over the extended query protocol (sql_single_statement); values in the params array are bound to $1, $2 placeholders and cannot protect SQL already interpolated into the text. PGlite.exec(sql) runs every statement in its text over the simple query protocol and binds nothing (sql_multi_statement). The sql tagged template binds each substitution as a parameter. A transaction's tx.query and tx.exec behave the same."}
	}
	if id == "sqljs-statement-v1" {
		return &analysis.APIModel{ID: "sqljs-statement-v1", Library: "sql.js", Semantics: "sql.js Database run, exec and prepare take executable SQL text as their first argument; run and exec execute every statement in that text. A second argument, or Statement bind, supplies separate values for placeholders and cannot protect SQL already interpolated into the text.", Reference: "https://sql.js.org/documentation/Database.html"}
	}
	for _, driver := range []string{"sqlite3", "psycopg", "psycopg2", "pymysql", "mysql.connector"} {
		v := PythonContract(driver)
		if v.ID == id {
			return v
		}
	}
	for _, driver := range []string{"mysqli", "pdo", "sqlite3", "doctrine-dbal", "doctrine-orm"} {
		if v := PHPSQLContract(driver); v.ID == id {
			return v
		}
	}
	return nil
}

// JavaScriptSQLLibrary reports a SQL contract that belongs to the JS/TS adapter.
func JavaScriptSQLLibrary(library string) bool {
	return library == "sequelize" || library == "sql.js" || library == "prisma" || library == "better-sqlite3" || library == "pglite" || library == "package"
}

// PHPSQLContractIDs lists the PHP per-engine SQL contracts (D-5).
var PHPSQLContractIDs = []string{"php-mysqli-v1", "php-pdo-v1", "php-sqlite3-v1"}

// PHPSQLContract returns the per-engine operation contract. mysqli covers the
// procedural API and the OO API; the $GLOBALS["___mysqli_ston"] converter
// idiom is normalized to the verified connection handle by the adapter.
func PHPSQLContract(driver string) *analysis.APIModel {
	switch driver {
	case "mysqli":
		return &analysis.APIModel{ID: "php-mysqli-v1", Library: "mysqli", Reference: "https://www.php.net/manual/en/mysqli.query.php",
			Semantics: "mysqli_query and mysqli::query execute every statement in their SQL text argument (argument 1 in the procedural form; the connection provenance is supplied separately). mysqli_multi_query runs multiple semicolon-separated statements. mysqli_prepare compiles one statement with ? placeholders; mysqli_stmt_bind_param/execute supply separate values for those placeholders and cannot protect SQL already interpolated into the prepared text. mysqli_real_escape_string escapes SQL syntax for the current connection charset; it is a value transform recorded as evidence, never a binding or a protection verdict, and it does not escape identifiers. Connection/cursor provenance is supplied separately; this contract is not evidence that the caller uses it correctly."}
	case "pdo":
		return &analysis.APIModel{ID: "php-pdo-v1", Library: "pdo", Reference: "https://www.php.net/manual/en/pdo.query.php",
			Semantics: "PDO::query and PDO::exec run the SQL text argument and bind nothing. PDO::prepare compiles one statement with named (:name) or positional (?) placeholders; PDOStatement::bindParam/bindValue supply separate values and cannot protect SQL already interpolated into the prepared text; PDOStatement::execute with a value array behaves the same. emulate_prepares does not change the text/data separation. Connection/statement provenance is supplied separately; this contract is not evidence that the caller uses it correctly."}
	case "sqlite3":
		return &analysis.APIModel{ID: "php-sqlite3-v1", Library: "sqlite3", Reference: "https://www.php.net/manual/en/sqlite3.query.php",
			Semantics: "SQLite3::query and SQLite3::exec run the SQL text argument; exec runs every statement in the text and binds nothing. SQLite3::prepare compiles one statement with named or positional placeholders; SQLite3Stmt::bindValue/execute supply separate values and cannot protect SQL already interpolated into the prepared text. Connection provenance is supplied separately; this contract is not evidence that the caller uses it correctly."}
	case "doctrine-dbal":
		return &analysis.APIModel{ID: PHPDoctrineDBALContract, Library: "doctrine-dbal", Reference: "https://www.doctrine-project.org/projects/doctrine-dbal/en/3.10/reference/data-retrieval-and-manipulation.html",
			Semantics: "Doctrine DBAL Connection executeQuery, executeStatement, fetchOne, fetchAssociative, fetchNumeric, fetchAllAssociative, fetchAllNumeric, fetchFirstColumn and iterateAssociative take executable SQL text at argument 0 and separate parameter values at argument 1. prepare captures its argument 0 as the statement text. Statement bindValue and bindParam bind argument 1 to the placeholder selected by argument 0. Statement executeQuery and executeStatement execute the prepared text, with separately supplied data values and prior bindings. A parameter can fill a literal placeholder without protecting SQL already assembled into query text."}
	case "doctrine-orm":
		return &analysis.APIModel{ID: PHPDoctrineORMContract, Library: "doctrine-orm", Reference: "https://www.doctrine-project.org/projects/doctrine-orm/en/2.20/reference/query-builder.html",
			Semantics: "Doctrine ORM EntityManager createQuery and createNativeQuery take executable DQL or SQL text at argument 0. QueryBuilder where, having, select, orderBy and groupBy and their supported add/and/or variants take executable string fragments, as does set. join, innerJoin and leftJoin take the executable condition at argument 3. setParameter binds argument 1 to the placeholder identified by argument 0, and setParameters holds the bindings at argument 0. getQuery constructs the query; execute and the result methods execute its text. Value bindings cannot protect fragments or identifiers already assembled into query text."}
	}
	return nil
}

// PythonContract applies only after import/connection/cursor provenance resolves.
func PythonContract(driver string) *analysis.APIModel {
	reference, placeholder := "", "%s or %(name)s"
	switch driver {
	case "sqlite3":
		reference = "https://docs.python.org/3/library/sqlite3.html#sqlite3.Cursor.execute"
		placeholder = "? or :name"
	case "psycopg":
		reference = "https://www.psycopg.org/psycopg3/docs/basic/params.html"
	case "psycopg2":
		reference = "https://www.psycopg.org/docs/usage.html#passing-parameters-to-sql-queries"
	case "pymysql":
		reference = "https://pymysql.readthedocs.io/en/latest/modules/cursors.html#pymysql.cursors.Cursor.execute"
	case "mysql.connector":
		reference = "https://dev.mysql.com/doc/connector-python/en/connector-python-api-mysqlcursor-execute.html"
	default:
		return nil
	}
	return &analysis.APIModel{ID: "python-" + driver + "-dbapi-v1", Library: driver, Reference: reference, Semantics: "execute/executemany SQL text is argument 0; argument 1 supplies separate value parameters using " + placeholder + " placeholders for this driver. Placeholders must not be quoted. Bound values cannot protect SQL already interpolated or dynamic identifiers. SQLite executescript does not bind parameters. Connection/cursor provenance is supplied separately; this contract is not evidence that the caller uses it correctly."}
}
