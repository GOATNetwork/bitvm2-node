CREATE TABLE graph_compensation_marker (
    graph_id BLOB NOT NULL,
    message_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (graph_id, message_id)
);
