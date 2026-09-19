// Small in-house line diff so a reviewer sees the exact change, with no extra dependency.
const MAX_DIFF_LINES = 400
const MARKERS = { context: ' ', removed: '-', added: '+' }

const splitLines = (value) => {
  const text = String(value ?? '').replace(/\r\n?/g, '\n')
  if (text === '') return []
  const lines = text.split('\n')
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop()
  return lines
}

function longestCommonRows(before, after) {
  const rows = []
  const table = Array.from({ length: before.length + 1 }, () => new Uint32Array(after.length + 1))
  for (let i = before.length - 1; i >= 0; i -= 1) {
    for (let j = after.length - 1; j >= 0; j -= 1) {
      table[i][j] = before[i] === after[j]
        ? table[i + 1][j + 1] + 1
        : Math.max(table[i + 1][j], table[i][j + 1])
    }
  }
  let i = 0
  let j = 0
  while (i < before.length && j < after.length) {
    if (before[i] === after[j]) { rows.push({ type: 'context', text: before[i] }); i += 1; j += 1 }
    else if (table[i + 1][j] >= table[i][j + 1]) { rows.push({ type: 'removed', text: before[i] }); i += 1 }
    else { rows.push({ type: 'added', text: after[j] }); j += 1 }
  }
  while (i < before.length) { rows.push({ type: 'removed', text: before[i] }); i += 1 }
  while (j < after.length) { rows.push({ type: 'added', text: after[j] }); j += 1 }
  return rows
}

export function diffRows(original, replacement) {
  const before = splitLines(original)
  const after = splitLines(replacement)
  if (before.length > MAX_DIFF_LINES || after.length > MAX_DIFF_LINES) {
    return [
      ...before.map((text) => ({ type: 'removed', text })),
      ...after.map((text) => ({ type: 'added', text })),
    ]
  }
  return longestCommonRows(before, after)
}

export function unifiedDiff(original, replacement, { path = 'file', startLine = 1 } = {}) {
  const rows = diffRows(original, replacement)
  const removed = rows.filter((row) => row.type !== 'added').length
  const added = rows.filter((row) => row.type !== 'removed').length
  const start = Number.isFinite(Number(startLine)) && Number(startLine) > 0 ? Number(startLine) : 1
  return {
    path,
    header: [`--- a/${path}`, `+++ b/${path}`, `@@ -${start},${removed} +${start},${added} @@`],
    rows: rows.map((row) => ({ ...row, line: `${MARKERS[row.type]}${row.text}` })),
  }
}
