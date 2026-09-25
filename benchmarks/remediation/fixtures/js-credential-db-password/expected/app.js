// Warehouse connection settings.
const config = {
  host: 'warehouse.internal',
  port: 5432,
  user: 'warehouse_app',
  password: process.env.PASSWORD,
  database: 'warehouse',
};

function dsn() {
  return `postgresql://${config.user}:${config.password}@${config.host}:${config.port}/${config.database}`;
}

module.exports = { config, dsn };
