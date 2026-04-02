import { Request, Response, NextFunction } from 'express';
import { QueryTypes, Sequelize } from 'sequelize';
import models from './models';
import utils from './utils';

interface ErrorWithParent extends Error {
  parent?: Error;
}

function escapeLike(search: string): string {
  return search.replace(/[%_\\]/g, '\\$&');
}

function isValidInput(input: unknown): input is string {
  return typeof input === 'string' && input.trim().length > 0;
}

const MAX_CRITERIA_LENGTH = 200;

function sanitizeInput(input: string): string {
  return input.length <= MAX_CRITERIA_LENGTH ? escapeLike(input) : escapeLike(input.substring(0, MAX_CRITERIA_LENGTH));
}

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawCriteria = req.query.q;
      const criteria = isValidInput(rawCriteria) ? rawCriteria : '';
      const sanitizedCriteria = sanitizeInput(criteria);

      const products: Array<{ name: string; description: string }> = await models.sequelize.query(
        "SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name",
        {
          replacements: { search: `%${sanitizedCriteria}%` },
          type: QueryTypes.SELECT,
          raw: true,
          logging: false, // Disable logging for sensitive queries
        }
      );

      for (const product of products) {
        product.name = req.__(product.name);
        product.description = req.__(product.description);
      }

      res.json(utils.queryResultToJson(products));
    } catch (error) {
      next((error as ErrorWithParent).parent || error);
    }
  };
};