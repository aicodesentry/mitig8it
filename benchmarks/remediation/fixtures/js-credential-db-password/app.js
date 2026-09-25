// Warehouse connection settings.
const config = {
  host: 'warehouse.internal',
  port: 5432,
  user: 'warehouse_app',
  password: 'Pa55w0rd-warehouse-2026',
  database: 'warehouse',
};

function dsn() {
  return `postgresql://${config.user}:${config.password}@${config.host}:${config.port}/${config.database}`;
}

module.exports = { config, dsn };
