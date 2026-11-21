// Controls: a local declaration replaces the built-in, so the listed keys are
// not the keys of the source.
function shadowedReflect(target, source) {
  class Reflect {
    static ownKeys() { return ['fixed']; }
  }
  Reflect.ownKeys(source).forEach((key) => {
    if (source[key] && typeof source[key] === 'object') shadowedReflect(target[key], source[key]);
    else target[key] = source[key];
  });
}

function shadowedObject(target, source) {
  function Object() {}
  Object.getOwnPropertyNames = () => ['fixed'];
  for (const key of Object.getOwnPropertyNames(source)) {
    if (source[key] && typeof source[key] === 'object') shadowedObject(target[key], source[key]);
    else target[key] = source[key];
  }
}

module.exports = { shadowedReflect, shadowedObject };
