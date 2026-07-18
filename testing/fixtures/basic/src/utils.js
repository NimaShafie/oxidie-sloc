'use strict';

/**
 * Compact SI formatter — mirrors the canonical fmt() helper used in the web UI.
 * @param {number} n
 * @returns {string}
 */
function fmt(n) {
    const v = Number(n);
    const a = Math.abs(v);
    if (a >= 1e6) return (v / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    if (a >= 1e4) return Math.round(v / 1e3) + 'K';
    return v.toLocaleString();
}

/**
 * Returns n.toLocaleString() — full precision for tooltips.
 * @param {number} n
 * @returns {string}
 */
function fmtFull(n) {
    return Number(n).toLocaleString();
}

/**
 * Debounce: delays fn until delay ms have passed since the last call.
 * @param {Function} fn
 * @param {number} delay  milliseconds
 * @returns {Function}
 */
function debounce(fn, delay) {
    let timer = null;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
}

/**
 * Deep-merges source into a shallow copy of target.
 * Arrays in source overwrite their counterpart in target (no concat).
 * @param {Object} target
 * @param {Object} source
 * @returns {Object}
 */
function merge(target, source) {
    const result = Object.assign({}, target);
    for (const [key, val] of Object.entries(source)) {
        result[key] =
            val !== null && typeof val === 'object' && !Array.isArray(val)
                ? merge(result[key] != null ? result[key] : {}, val)
                : val;
    }
    return result;
}

/**
 * Builds a query string from a plain object.  Skips null / undefined values.
 * @param {Object} params
 * @returns {string}  leading '?' included when non-empty
 */
function toQueryString(params) {
    const parts = [];
    for (const [k, v] of Object.entries(params)) {
        if (v == null) continue;
        parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
    return parts.length ? '?' + parts.join('&') : '';
}

module.exports = { fmt, fmtFull, debounce, merge, toQueryString };
