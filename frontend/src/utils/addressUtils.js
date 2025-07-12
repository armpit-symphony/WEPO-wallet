/**
 * WEPO Address Standardization System
 * Unified address generation, validation, and formatting
 */

import CryptoJS from 'crypto-js';

// Address format constants
export const ADDRESS_FORMATS = {
  WEPO_REGULAR: {
    prefix: 'wepo1',
    payloadLength: 32,
    totalLength: 37, // wepo1 + 32 chars
    type: 'regular'
  },
  WEPO_QUANTUM: {
    prefix: 'wepo1q',
    payloadLength: 39,
    totalLength: 45, // wepo1q + 39 chars  
    type: 'quantum'
  },
  BTC: {
    prefix: '1',
    payloadLength: 25,
    totalLength: 34, // Future BTC integration
    type: 'bitcoin'
  }
};

/**
 * Generate standardized WEPO address from seed
 * @param {string|Buffer} seed - Wallet seed
 * @param {string} type - 'regular' or 'quantum'
 * @returns {string} Standardized WEPO address
 */
export const generateWepoAddress = (seed, type = 'regular') => {
  const seedString = typeof seed === 'string' ? seed : seed.toString('hex');
  const hash = CryptoJS.SHA256(seedString).toString();
  
  if (type === 'quantum') {
    const format = ADDRESS_FORMATS.WEPO_QUANTUM;
    const payload = hash.substring(0, format.payloadLength);
    return `${format.prefix}${payload}`;
  } else {
    const format = ADDRESS_FORMATS.WEPO_REGULAR;
    const payload = hash.substring(0, format.payloadLength);
    return `${format.prefix}${payload}`;
  }
};

/**
 * Validate WEPO address format
 * @param {string} address - Address to validate
 * @returns {object} Validation result with type detection
 */
export const validateWepoAddress = (address) => {
  if (!address || typeof address !== 'string') {
    return { 
      valid: false, 
      type: null, 
      error: 'Address must be a string' 
    };
  }

  // Check for regular WEPO address
  if (address.startsWith(ADDRESS_FORMATS.WEPO_REGULAR.prefix) && 
      !address.startsWith(ADDRESS_FORMATS.WEPO_QUANTUM.prefix)) {
    
    if (address.length === ADDRESS_FORMATS.WEPO_REGULAR.totalLength) {
      return { 
        valid: true, 
        type: 'regular', 
        format: ADDRESS_FORMATS.WEPO_REGULAR 
      };
    } else {
      return { 
        valid: false, 
        type: 'regular', 
        error: `Regular WEPO address must be ${ADDRESS_FORMATS.WEPO_REGULAR.totalLength} characters` 
      };
    }
  }

  // Check for quantum WEPO address
  if (address.startsWith(ADDRESS_FORMATS.WEPO_QUANTUM.prefix)) {
    if (address.length === ADDRESS_FORMATS.WEPO_QUANTUM.totalLength) {
      return { 
        valid: true, 
        type: 'quantum', 
        format: ADDRESS_FORMATS.WEPO_QUANTUM 
      };
    } else {
      return { 
        valid: false, 
        type: 'quantum', 
        error: `Quantum WEPO address must be ${ADDRESS_FORMATS.WEPO_QUANTUM.totalLength} characters` 
      };
    }
  }

  return { 
    valid: false, 
    type: null, 
    error: 'Address must start with wepo1 (regular) or wepo1q (quantum)' 
  };
};

/**
 * Detect address type from address string
 * @param {string} address - Address to analyze
 * @returns {string|null} Address type or null if invalid
 */
export const getAddressType = (address) => {
  const validation = validateWepoAddress(address);
  return validation.valid ? validation.type : null;
};

/**
 * Check if address is quantum-resistant
 * @param {string} address - Address to check
 * @returns {boolean} True if quantum-resistant
 */
export const isQuantumAddress = (address) => {
  return getAddressType(address) === 'quantum';
};

/**
 * Format address for display (truncate middle)
 * @param {string} address - Full address
 * @param {number} startChars - Characters to show at start
 * @param {number} endChars - Characters to show at end
 * @returns {string} Formatted address
 */
export const formatAddressForDisplay = (address, startChars = 8, endChars = 6) => {
  if (!address || address.length <= startChars + endChars) {
    return address;
  }
  
  return `${address.substring(0, startChars)}...${address.substring(address.length - endChars)}`;
};

/**
 * Convert legacy address to standardized format
 * @param {string} legacyAddress - Old format address
 * @returns {string} Standardized address
 */
export const standardizeAddress = (legacyAddress) => {
  if (!legacyAddress || !legacyAddress.startsWith('wepo1')) {
    return legacyAddress;
  }

  // Handle legacy 45-char addresses (convert to quantum format)
  if (legacyAddress.length === 45 && !legacyAddress.startsWith('wepo1q')) {
    // Convert to new quantum format
    const payload = legacyAddress.substring(5, 44); // Remove 'wepo1', take 39 chars
    return `wepo1q${payload}`;
  }

  // Handle legacy 37-char addresses (already standard regular format)
  if (legacyAddress.length === 37) {
    return legacyAddress; // Already in correct format
  }

  // Return as-is if doesn't match expected patterns
  return legacyAddress;
};

/**
 * Generate address validation regex patterns
 * @returns {object} Regex patterns for different address types
 */
export const getAddressPatterns = () => {
  return {
    regular: new RegExp(`^${ADDRESS_FORMATS.WEPO_REGULAR.prefix}[a-f0-9]{${ADDRESS_FORMATS.WEPO_REGULAR.payloadLength}}$`),
    quantum: new RegExp(`^${ADDRESS_FORMATS.WEPO_QUANTUM.prefix}[a-f0-9]{${ADDRESS_FORMATS.WEPO_QUANTUM.payloadLength}}$`),
    any: new RegExp(`^wepo1q?[a-f0-9]{32,39}$`)
  };
};

/**
 * Check if two addresses are equivalent (handles legacy formats)
 * @param {string} address1 - First address
 * @param {string} address2 - Second address
 * @returns {boolean} True if addresses are equivalent
 */
export const addressesEqual = (address1, address2) => {
  if (!address1 || !address2) return false;
  
  const std1 = standardizeAddress(address1);
  const std2 = standardizeAddress(address2);
  
  return std1 === std2;
};

/**
 * Batch validate multiple addresses
 * @param {string[]} addresses - Array of addresses to validate
 * @returns {object[]} Array of validation results
 */
export const validateAddressBatch = (addresses) => {
  return addresses.map(address => ({
    address,
    ...validateWepoAddress(address)
  }));
};

export default {
  ADDRESS_FORMATS,
  generateWepoAddress,
  validateWepoAddress,
  getAddressType,
  isQuantumAddress,
  formatAddressForDisplay,
  standardizeAddress,
  getAddressPatterns,
  addressesEqual,
  validateAddressBatch
};