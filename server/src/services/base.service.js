class BaseService {
    constructor(repository) {
        this.repository = repository;
    }

    async create(data) {
        try {
            return await this.repository.create(data);
        } catch (error) {
            throw new Error(`Service error creating resource: ${error.message}`);
        }
    }

    async findById(id, options = {}) {
        try {
            if (!id) {
                throw new Error('ID is required');
            }
            return await this.repository.findById(id, options);
        } catch (error) {
            throw new Error(`Service error finding resource by ID: ${error.message}`);
        }
    }

    async findOne(filter, options = {}) {
        try {
            return await this.repository.findOne(filter, options);
        } catch (error) {
            throw new Error(`Service error finding resource: ${error.message}`);
        }
    }

    async find(filter = {}, options = {}) {
        try {
            return await this.repository.find(filter, options);
        } catch (error) {
            throw new Error(`Service error finding resources: ${error.message}`);
        }
    }

    async updateById(id, updateData, options = {}) {
        try {
            if (!id) {
                throw new Error('ID is required');
            }
            return await this.repository.updateById(id, updateData, options);
        } catch (error) {
            throw new Error(`Service error updating resource: ${error.message}`);
        }
    }

    async updateOne(filter, updateData, options = {}) {
        try {
            return await this.repository.updateOne(filter, updateData, options);
        } catch (error) {
            throw new Error(`Service error updating resource: ${error.message}`);
        }
    }

    async deleteById(id) {
        try {
            if (!id) {
                throw new Error('ID is required');
            }
            return await this.repository.deleteById(id);
        } catch (error) {
            throw new Error(`Service error deleting resource: ${error.message}`);
        }
    }

    async deleteOne(filter) {
        try {
            return await this.repository.deleteOne(filter);
        } catch (error) {
            throw new Error(`Service error deleting resource: ${error.message}`);
        }
    }

    async count(filter = {}) {
        try {
            return await this.repository.count(filter);
        } catch (error) {
            throw new Error(`Service error counting resources: ${error.message}`);
        }
    }

    async exists(filter) {
        try {
            return await this.repository.exists(filter);
        } catch (error) {
            throw new Error(`Service error checking resource existence: ${error.message}`);
        }
    }

    
    validateRequiredFields(data, requiredFields) {
        const missingFields = requiredFields.filter(field => 
            data[field] === undefined || data[field] === null || data[field] === ''
        );

        if (missingFields.length > 0) {
            throw new Error(`Missing required fields: ${missingFields.join(', ')}`);
        }
    }

    sanitizeData(data) {
        const sanitized = {};
        Object.keys(data).forEach(key => {
            if (data[key] !== undefined && data[key] !== null) {
                sanitized[key] = data[key];
            }
        });
        return sanitized;
    }

    formatResponse(data, options = {}) {
        const response = {
            success: true,
            data
        };

        if (options.message) {
            response.message = options.message;
        }

        if (options.meta) {
            response.meta = options.meta;
        }

        return response;
    }


    handleError(error, operation = 'operation') {
        console.error(`Service error during ${operation}:`, error);
        
        if (error.name === 'ValidationError') {
            throw new Error(`Validation failed: ${error.message}`);
        }
        
        if (error.name === 'CastError') {
            throw new Error(`Invalid ID format: ${error.message}`);
        }
        
        throw error;
    }
}

module.exports = BaseService;