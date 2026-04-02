import { Request, Response, NextFunction } from 'express';
import { Sequelize } from 'sequelize';
import { models } from './models'; // Assuming you have a models file that exports sequelize models
import { utils } from './utils'; // Assuming you have a utils file
import { ErrorWithParent } from './types'; // Assuming you have a types file

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const query = req.query.q;
      let criteria = typeof query === 'string' ? query : '';
      criteria = criteria.slice(0, 200);

      const [products] = await models.sequelize.query(
        'SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name',
        {
          replacements: { search: `%${criteria.replace(/%/g, '\\%').replace(/_/g, '\\_')}%` },
          type: Sequelize.QueryTypes.SELECT,
        }
      );

      for (const product of products) {
        if (typeof product.name === 'string') {
          product.name = req.__(product.name);
        }
        if (typeof product.description === 'string') {
          product.description = req.__(product.description);
        }
      }

      res.json(utils.queryResultToJson(products));
    } catch (error) {
      next((error as ErrorWithParent).parent || error);
    }
  };
};