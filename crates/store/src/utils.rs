#[derive(Clone)]
pub struct QueryBuilder {
    sql: String,
    params: Vec<QueryParam>,
}

#[derive(Clone)]
pub enum QueryParam {
    Text(String),
    Int(i64),
}

impl QueryBuilder {
    pub fn get_sql(&self) -> String {
        self.sql.clone()
    }

    pub fn get_params(&self) -> Vec<QueryParam> {
        self.params.clone()
    }
    pub fn new(base_sql: &str) -> Self {
        Self { sql: base_sql.to_string(), params: Vec::new() }
    }

    /// Create a new UPDATE query builder
    pub fn update(table: &str) -> Self {
        Self { sql: format!("UPDATE {table}"), params: Vec::new() }
    }

    /// Add SET clause for UPDATE queries
    pub fn set_field(&mut self, field: &str, param: QueryParam) {
        if self.sql.contains("SET") {
            self.sql.push_str(&format!(", {field} = ?"));
        } else {
            self.sql.push_str(&format!(" SET {field} = ?"));
        }
        self.params.push(param);
    }

    /// Add SET clause with NULL value for UPDATE queries
    pub fn set_field_null(&mut self, field: &str) {
        if self.sql.contains("SET") {
            self.sql.push_str(&format!(", {field} = NULL"));
        } else {
            self.sql.push_str(&format!(" SET {field} = NULL"));
        }
    }

    /// Add multiple SET fields for UPDATE queries
    #[allow(dead_code)]
    pub fn set_fields(&mut self, fields: &[(&str, QueryParam)]) {
        for (field, param) in fields {
            self.set_field(field, param.clone());
        }
    }

    pub fn and_where(&mut self, condition: &str, param: Option<QueryParam>) {
        let clause = if self.sql.contains("WHERE") { "AND" } else { "WHERE" };

        self.sql.push_str(&format!(" {clause} {condition}"));

        if let Some(p) = param {
            self.params.push(p);
        }
    }

    #[allow(dead_code)]
    pub fn add_raw_condition(&mut self, condition: &str) {
        let clause = if self.sql.contains("WHERE") { "AND" } else { "WHERE" };
        self.sql.push_str(&format!(" {clause} {condition}"));
    }

    pub fn apply_order(&mut self, field: &str) {
        self.sql.push_str(&format!(" ORDER BY {field}"));
    }

    pub fn apply_pagination(&mut self, limit: Option<u32>, offset: Option<u32>) {
        if let Some(limit) = limit {
            self.sql.push_str(&format!(" LIMIT {limit}"));
        }

        if let Some(offset) = offset {
            self.sql.push_str(&format!(" OFFSET {offset}"));
        }
    }
}
