class BaseRepository {
    constructor(model) {
        this.model = model;
    }

    async findById(id, options = {}) {
        try {
            let query = this.model.findById(id);
            
            if (options.select) {
                query = query.select(options.select);
            }
            
            if (options.populate) {
                query = query.populate(options.populate);
            }
            
            return await query.exec();
        } catch (error) {
            throw new Error(`Error finding document by ID: ${error.message}`);
        }
    }

    async findOne(filter, options = {}) {
        try {
            let query = this.model.findOne(filter);
            
            if (options.select) {
                query = query.select(options.select);
            }
            
            if (options.populate) {
                query = query.populate(options.populate);
            }
            
            return await query.exec();
        } catch (error) {
            throw new Error(`Error finding document: ${error.message}`);
        }
    }

    async find(filter = {}, options = {}) {
        try {
            let query = this.model.find(filter);
            
            if (options.select) {
                query = query.select(options.select);
            }
            
            if (options.populate) {
                query = query.populate(options.populate);
            }
            
            if (options.sort) {
                query = query.sort(options.sort);
            }
            
            if (options.limit) {
                query = query.limit(options.limit);
            }
            
            if (options.skip) {
                query = query.skip(options.skip);
            }
            
            return await query.exec();
        } catch (error) {
            throw new Error(`Error finding documents: ${error.message}`);
        }
    }

    async create(data) {
        try {
            return await this.model.create(data);
        } catch (error) {
            throw new Error(`Error creating document: ${error.message}`);
        }
    }

    async updateById(id, updateData, options = {}) {
        try {
            const defaultOptions = { new: true, runValidators: true };
            const mergedOptions = { ...defaultOptions, ...options };
            
            return await this.model.findByIdAndUpdate(id, updateData, mergedOptions);
        } catch (error) {
            throw new Error(`Error updating document: ${error.message}`);
        }
    }

    async updateOne(filter, updateData, options = {}) {
        try {
            const defaultOptions = { new: true, runValidators: true };
            const mergedOptions = { ...defaultOptions, ...options };
            
            return await this.model.findOneAndUpdate(filter, updateData, mergedOptions);
        } catch (error) {
            throw new Error(`Error updating document: ${error.message}`);
        }
    }

    async deleteById(id) {
        try {
            return await this.model.findByIdAndDelete(id);
        } catch (error) {
            throw new Error(`Error deleting document: ${error.message}`);
        }
    }

    async deleteOne(filter) {
        try {
            return await this.model.findOneAndDelete(filter);
        } catch (error) {
            throw new Error(`Error deleting document: ${error.message}`);
        }
    }

    async count(filter = {}) {
        try {
            return await this.model.countDocuments(filter);
        } catch (error) {
            throw new Error(`Error counting documents: ${error.message}`);
        }
    }

    async exists(filter) {
        try {
            const result = await this.model.exists(filter);
            return !!result;
        } catch (error) {
            throw new Error(`Error checking document existence: ${error.message}`);
        }
    }

    async aggregate(pipeline) {
        try {
            return await this.model.aggregate(pipeline);
        } catch (error) {
            throw new Error(`Error executing aggregation: ${error.message}`);
        }
    }

    async bulkWrite(operations, options = {}) {
        try {
            return await this.model.bulkWrite(operations, options);
        } catch (error) {
            throw new Error(`Error executing bulk write: ${error.message}`);
        }
    }
}

module.exports = BaseRepository;