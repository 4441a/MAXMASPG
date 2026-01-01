// furui_dsp_library.js (JavaScript version for Max/MSP)
// Inspired by Sadao Furui's "Digital Speech Processing, Synthesis, and Recognition"
// Implements key algorithms for educational purposes.
// Uses TypedArrays for optimization; no external libraries.
// Revisions: Fixed Levinson-Durbin signs for correct LPC coeffs; removed autocorrelation normalization for stability; removed duplicate cepstral function.

// Utility: Complex number class for FFT
function Complex(re, im) {
  this.re = re || 0;
  this.im = im || 0;
}

Complex.prototype.add = function(other) {
  return new Complex(this.re + other.re, this.im + other.im);
};

Complex.prototype.sub = function(other) {
  return new Complex(this.re - other.re, this.im - other.im);
};

Complex.prototype.mul = function(other) {
  const r = this.re * other.re - this.im * other.im;
  const i = this.re * other.im + this.im * other.re;
  return new Complex(r, i);
};

Complex.prototype.cexp = function() {
  const er = Math.exp(this.re);
  return new Complex(er * Math.cos(this.im), er * Math.sin(this.im));
};

// FFT implementation (recursive Cooley-Tukey; assumes power-of-2 length)
function cfft(amplitudes) {
  const N = amplitudes.length;
  if (N <= 1) return amplitudes;
  const hN = N / 2;
  const even = new Array(hN);
  const odd = new Array(hN);
  for (let i = 0; i < hN; ++i) {
    even[i] = amplitudes[i * 2];
    odd[i] = amplitudes[i * 2 + 1];
  }
  const evenFFT = cfft(even);
  const oddFFT = cfft(odd);
  const a = -2 * Math.PI;
  for (let k = 0; k < hN; ++k) {
    if (!(evenFFT[k] instanceof Complex)) evenFFT[k] = new Complex(evenFFT[k], 0);
    if (!(oddFFT[k] instanceof Complex)) oddFFT[k] = new Complex(oddFFT[k], 0);
    const p = k / N;
    const t = new Complex(0, a * p).cexp();
    t.mul(oddFFT[k]);
    amplitudes[k] = evenFFT[k].add(t);
    amplitudes[k + hN] = evenFFT[k].sub(t);
  }
  return amplitudes;
}

// IFFT (inverse FFT)
function icfft(amplitudes) {
  const N = amplitudes.length;
  const iN = 1 / N;
  for (let i = 0; i < N; ++i) {
    if (amplitudes[i] instanceof Complex) amplitudes[i].im = -amplitudes[i].im;
  }
  amplitudes = cfft(amplitudes);
  for (let i = 0; i < N; ++i) {
    amplitudes[i].im = -amplitudes[i].im;
    amplitudes[i].re *= iN;
    amplitudes[i].im *= iN;
  }
  return amplitudes;
}

// Simple autocorrelation (raw sum, no normalization for LPC stability)
function autocorr(signal) {
  const n = signal.length;
  const ac = new Float64Array(n);
  for (let lag = 0; lag < n; lag++) {
    let sum = 0;
    for (let i = 0; i < n - lag; i++) {
      sum += signal[i] * signal[i + lag];
    }
    ac[lag] = sum;
  }
  return ac;
}

// Levinson-Durbin for LPC coefficients (returns filter coeffs [1, -pred1, -pred2, ...])
function levinsonDurbin(R, order) {
  const a = new Float64Array(order + 1);
  const e = new Float64Array(order + 1);
  a[0] = 1;
  e[0] = R[0];
  for (let m = 1; m <= order; m++) {
    let sum = R[m];
    for (let j = 1; j < m; j++) {
      sum += a[j] * R[m - j];
    }
    const k = -sum / e[m - 1];
    a[m] = k;
    for (let j = 1; j < m; j++) {
      a[j] += k * a[m - j];
    }
    e[m] = e[m - 1] * (1 - k * k);
  }
  return a;
}

// Simple IIR filter for synthesis (denom coeffs [1, a1, a2, ...])
function iirFilter(input, coeffs, gain = 1.0) {
  const output = new Float64Array(input.length);
  const order = coeffs.length - 1;
  const state = new Float64Array(order);
  for (let i = 0; i < input.length; i++) {
    let acc = input[i] * gain;
    for (let j = 1; j <= order; j++) {
      acc -= coeffs[j] * state[j - 1];
    }
    output[i] = acc;
    for (let j = order - 1; j > 0; j--) {
      state[j] = state[j - 1];
    }
    state[0] = acc;
  }
  return output;
}

// Simple linear interpolation resampler (fs parameters are effective rates; can be sample counts if duration fixed)
function resample(signal, oldFs, newFs) {
  const ratio = oldFs / newFs;
  const newLength = Math.ceil(signal.length / ratio);
  const output = new Float64Array(newLength);
  for (let i = 0; i < newLength; i++) {
    const pos = i * ratio;
    const low = Math.floor(pos);
    const frac = pos - low;
    if (low + 1 < signal.length) {
      output[i] = signal[low] * (1 - frac) + signal[low + 1] * frac;
    } else {
      output[i] = signal[low];
    }
  }
  return output;
}

// Cepstral analysis
function cepstralAnalysis(signal, nCeps = 13) {
  const N = signal.length;
  const spectrum = cfft(signal.map(v => new Complex(v, 0)));
  const logSpectrum = spectrum.map(c => Math.log(c.re * c.re + c.im * c.im + 1e-10) / 2); // log |spectrum|
  const cepstrum = icfft(logSpectrum.map(v => new Complex(v, 0)));
  return cepstrum.slice(0, nCeps).map(c => c.re); // Real part
}

// k-means for vector quantization (basic implementation)
function trainVqCodebook(features, codebookSize = 256, maxIter = 100, tol = 1e-4) {
  const N = features.length;
  const D = features[0].length;
  const codebook = new Array(codebookSize);
  for (let i = 0; i < codebookSize; i++) {
    codebook[i] = features[Math.floor(Math.random() * N)].slice();
  }
  for (let iter = 0; iter < maxIter; iter++) {
    const labels = new Array(N);
    const counts = new Array(codebookSize).fill(0);
    const newCodebook = Array.from({length: codebookSize}, () => new Array(D).fill(0));
    for (let j = 0; j < N; j++) {
      let minDist = Infinity;
      let minIdx = 0;
      for (let k = 0; k < codebookSize; k++) {
        let dist = 0;
        for (let d = 0; d < D; d++) {
          dist += (features[j][d] - codebook[k][d]) ** 2;
        }
        if (dist < minDist) {
          minDist = dist;
          minIdx = k;
        }
      }
      labels[j] = minIdx;
      counts[minIdx]++;
      for (let d = 0; d < D; d++) {
        newCodebook[minIdx][d] += features[j][d];
      }
    }
    let changed = false;
    for (let k = 0; k < codebookSize; k++) {
      if (counts[k] > 0) {
        for (let d = 0; d < D; d++) {
          newCodebook[k][d] /= counts[k];
        }
      }
      let dist = 0;
      for (let d = 0; d < D; d++) {
        dist += (newCodebook[k][d] - codebook[k][d]) ** 2;
      }
      if (Math.sqrt(dist) > tol) changed = true;
      codebook[k] = newCodebook[k];
    }
    if (!changed) break;
  }
  return codebook;
}

function vectorQuantization(codebook, features) {
  const indices = new Array(features.length);
  for (let i = 0; i < features.length; i++) {
    let minDist = Infinity;
    let minIdx = 0;
    for (let k = 0; k < codebook.length; k++) {
      let dist = 0;
      for (let d = 0; d < features[i].length; d++) {
        dist += (features[i][d] - codebook[k][d]) ** 2;
      }
      if (dist < minDist) {
        minDist = dist;
        minIdx = k;
      }
    }
    indices[i] = minIdx;
  }
  return indices;
}

// Main functions
function speechProductionModel(amplitude = 1.0, frequency = 100, duration = 1.0, fs = 16000) {
  const len = Math.floor(fs * duration);
  const waveform = new Float64Array(len);
  for (let i = 0; i < len; i++) {
    waveform[i] = amplitude * Math.sin(2 * Math.PI * frequency * i / fs);
  }
  return waveform;
}

function pitchDetectionAutocorr(signal, fs = 16000, minFreq = 80, maxFreq = 300) {
  const ac = autocorr(signal);
  const maxAuto = Math.max(...ac);
  if (maxAuto === 0) return 0.0;
  const normalized = ac.map(v => v / maxAuto);
  const minLag = Math.floor(fs / maxFreq);
  const maxLag = Math.floor(fs / minFreq);
  let peakLag = minLag;
  let maxVal = normalized[minLag];
  for (let i = minLag + 1; i < maxLag; i++) {
    if (normalized[i] > maxVal) {
      maxVal = normalized[i];
      peakLag = i;
    }
  }
  if (maxVal < 0.5) return 0.0;
  return fs / peakLag;
}

function lpcAnalysis(signal, order = 12, preemphasis = 0.97) {
  const len = signal.length;
  const preemp = new Float64Array(len);
  preemp[0] = signal[0];
  if (preemphasis > 0) {
    for (let i = 1; i < len; i++) {
      preemp[i] = signal[i] - preemphasis * signal[i - 1];
    }
  } else {
    preemp.set(signal);
  }
  const ac = autocorr(preemp).slice(0, order + 1);
  return levinsonDurbin(ac, order);
}

function lpcSynthesis(excitation, lpcCoeffs, gain = 1.0) {
  return iirFilter(excitation, lpcCoeffs, gain);
}

function waveformCodingSynthesis(originalSignal, bitRateReductionFactor = 2) {
  const numSamples = originalSignal.length;
  const reducedSamples = numSamples / bitRateReductionFactor;
  const downsampled = resample(originalSignal, numSamples, reducedSamples);
  return resample(downsampled, reducedSamples, numSamples);
}