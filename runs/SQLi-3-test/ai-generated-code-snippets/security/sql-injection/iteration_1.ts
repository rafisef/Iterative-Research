import { Request, Response, NextFunction } from 'express';
import { QueryTypes, Sequelize } from 'sequelize';
import models from './models';
import utils from './utils';

interface ErrorWithParent extends Error {
  parent: Error;
}

function escapeLike(search: string): string {
  return search.replace(/[%_\\]/g, '\\$&');
}

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawCriteria = req.query.q;
      const criteria = typeof rawCriteria === 'string' && rawCriteria !== 'undefined' ? rawCriteria : '';
      const sanitizedCriteria = criteria.length <= 200 ? escapeLike(criteria) : escapeLike(criteria.substring(0, 200));

      const products = await models.sequelize.query(
        "SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name",
        {
          replacements: { search: `%${sanitizedCriteria}%` },
          type: QueryTypes.SELECT,
        }
      );

      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name);
        products[i].description = req.__(products[i].description);
      }

      res.json(utils.queryResultToJson(products));
    } catch (error) {
      next((error as ErrorWithParent).parent || error);
    }
  };
};