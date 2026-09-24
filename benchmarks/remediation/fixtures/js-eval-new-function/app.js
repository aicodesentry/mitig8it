// Spreadsheet-style formulas compiled from a saved definition.
function compileFormula(source) {
  const compiled = new Function('row', `return ${source};`);
  return (row) => compiled(row);
}

module.exports = { compileFormula };
