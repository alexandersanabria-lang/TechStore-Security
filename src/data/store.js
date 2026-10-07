const users = [];
let currentId = 1;

function nextId() {
  return currentId++;
}

module.exports = { users, nextId };