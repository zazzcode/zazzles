<?php
const USERS_SQL = "SELECT id FROM users WHERE name = ";

class Queries {
    const BY_ID = "SELECT id FROM users WHERE id = ";

    public static function byId() {
        return self::BY_ID;
    }
}

function find_posts($author) {
    return "SELECT id FROM posts WHERE author = '" . $author . "'";
}
