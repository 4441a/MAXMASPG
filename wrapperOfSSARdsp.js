inlets = 1;  // For input messages/lists
outlets = 1;  // For output arrays/lists

include("furui_dsp_library.js");  // Load the library

function list() {
  var args = arrayfromargs(arguments);
  // Example: Convert Max list to Float64Array
  var signal = new Float64Array(args);
  var coeffs = lpcAnalysis(signal, 12);
  outlet(0, Array.from(coeffs));  // Output as Max list
}

function bang() {
  // Test synthesis
  var excitation = new Float64Array(512).map(() => Math.random() * 2 - 1);  // Noise
  var coeffs = new Float64Array([1, -1.6, 0.98]);  // Dummy LPC
  var synth = lpcSynthesis(excitation, coeffs);
  outlet(0, Array.from(synth.slice(0, 10)));  // Output first 10 samples
}