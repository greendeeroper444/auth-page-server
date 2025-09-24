const validator = require('validator');

const isValidEmail = (email) => {
    return validator.isEmail(email);
};

const validatePassword = (password) => {
    const errors = [];
    
    if (!password || password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }
    
    if (!/(?=.*[a-z])/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/(?=.*[A-Z])/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/(?=.*\d)/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    
    if (!/(?=.*[@$!%*?&])/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    
    if (password.length > 128) {
        errors.push('Password cannot exceed 128 characters');
    }
    
    return {
        isValid: errors.length === 0,
        errors
    };
};

const validateUsername = (username) => {
    const errors = [];
    
    if (!username) {
        errors.push('Username is required');
        return { isValid: false, errors };
    }
    
    if (username.length < 3) {
        errors.push('Username must be at least 3 characters long');
    }
    
    if (username.length > 30) {
        errors.push('Username cannot exceed 30 characters');
    }
    
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        errors.push('Username can only contain letters, numbers, hyphens, and underscores');
    }
    
    //check for reserved usernames
    const reservedUsernames = [
        'admin', 'administrator', 'root', 'api', 'www', 'mail', 'ftp',
        'system', 'user', 'test', 'guest', 'null', 'undefined'
    ];
    
    if (reservedUsernames.includes(username.toLowerCase())) {
        errors.push('This username is reserved');
    }
    
    return {
        isValid: errors.length === 0,
        errors
    };
};

const isValidPhone = (phone) => {
    if (!phone) return true;
    return validator.isMobilePhone(phone, 'any');
};

const validateName = (name, fieldName = 'Name') => {
    const errors = [];
    
    if (!name || !name.trim()) {
        errors.push(`${fieldName} is required`);
        return { isValid: false, errors };
    }
    
    if (name.trim().length < 2) {
        errors.push(`${fieldName} must be at least 2 characters long`);
    }
    
    if (name.length > 50) {
        errors.push(`${fieldName} cannot exceed 50 characters`);
    }
    
    if (!/^[a-zA-Z\s'-]+$/.test(name)) {
        errors.push(`${fieldName} can only contain letters, spaces, hyphens, and apostrophes`);
    }
    
    return {
        isValid: errors.length === 0,
        errors
    };
};

const validateDateOfBirth = (dateOfBirth) => {
    const errors = [];
    
    if (!dateOfBirth) {
        return { isValid: true, errors };
    }
    
    const date = new Date(dateOfBirth);
    const now = new Date();
    const minAge = new Date();
    minAge.setFullYear(now.getFullYear() - 13); //minimum age 13
    
    const maxAge = new Date();
    maxAge.setFullYear(now.getFullYear() - 120); //maximum age 120
    
    if (isNaN(date.getTime())) {
        errors.push('Please provide a valid date of birth');
    } else {
        if (date > now) {
            errors.push('Date of birth cannot be in the future');
        }
        
        if (date > minAge) {
            errors.push('You must be at least 13 years old');
        }
        
        if (date < maxAge) {
            errors.push('Please provide a valid date of birth');
        }
    }
    
    return {
        isValid: errors.length === 0,
        errors
    };
};

const sanitizeString = (str) => {
    if (typeof str !== 'string') return '';
    
    return validator.escape(str.trim());
};

const validateRegistrationData = (data) => {
    const errors = {};
    
    const firstNameValidation = validateName(data.firstName, 'First name');
    if (!firstNameValidation.isValid) {
        errors.firstName = firstNameValidation.errors;
    }
    
    const lastNameValidation = validateName(data.lastName, 'Last name');
    if (!lastNameValidation.isValid) {
        errors.lastName = lastNameValidation.errors;
    }
    
    if (!data.email) {
        errors.email = ['Email is required'];
    } else if (!isValidEmail(data.email)) {
        errors.email = ['Please provide a valid email address'];
    }
    
    const usernameValidation = validateUsername(data.username);
    if (!usernameValidation.isValid) {
        errors.username = usernameValidation.errors;
    }
    
    const passwordValidation = validatePassword(data.password);
    if (!passwordValidation.isValid) {
        errors.password = passwordValidation.errors;
    }

    if (data.phone && !isValidPhone(data.phone)) {
        errors.phone = ['Please provide a valid phone number'];
    }
    if (data.dateOfBirth) {
        const dobValidation = validateDateOfBirth(data.dateOfBirth);
        if (!dobValidation.isValid) {
            errors.dateOfBirth = dobValidation.errors;
        }
    }
    
    return {
        isValid: Object.keys(errors).length === 0,
        errors
    };
};

const validateLoginData = (data) => {
    const errors = {};
    
    if (!data.identifier) {
        errors.identifier = ['Email or username is required'];
    }
    
    if (!data.password) {
        errors.password = ['Password is required'];
    }
    
    return {
        isValid: Object.keys(errors).length === 0,
        errors
    };
};


const validateProfileUpdateData = (data) => {
    const errors = {};
    
    //only validate fields that are present
    if (data.firstName !== undefined) {
        const firstNameValidation = validateName(data.firstName, 'First name');
        if (!firstNameValidation.isValid) {
            errors.firstName = firstNameValidation.errors;
        }
    }
    
    if (data.lastName !== undefined) {
        const lastNameValidation = validateName(data.lastName, 'Last name');
        if (!lastNameValidation.isValid) {
            errors.lastName = lastNameValidation.errors;
        }
    }
    
    if (data.phone !== undefined && data.phone !== null && !isValidPhone(data.phone)) {
        errors.phone = ['Please provide a valid phone number'];
    }
    
    if (data.dateOfBirth !== undefined) {
        const dobValidation = validateDateOfBirth(data.dateOfBirth);
        if (!dobValidation.isValid) {
            errors.dateOfBirth = dobValidation.errors;
        }
    }
    
    return {
        isValid: Object.keys(errors).length === 0,
        errors
    };
};

module.exports = {
    isValidEmail,
    validatePassword,
    validateUsername,
    isValidPhone,
    validateName,
    validateDateOfBirth,
    sanitizeString,
    validateRegistrationData,
    validateLoginData,
    validateProfileUpdateData
};