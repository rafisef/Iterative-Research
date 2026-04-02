import { Request, Response, NextFunction } from 'express';
import models from './models';
import utils from './utils';

interface ErrorWithParent extends Error {
  parent: Error;
}

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawCriteria = req.query.q;
      const criteria = typeof rawCriteria === 'string' && rawCriteria !== 'undefined' ? rawCriteria.slice(0, 200) : '';
      
      const products = await models.sequelize.query(
        "SELECT * FROM Products WHERE ((name LIKE '%' || ? || '%' OR description LIKE '%' || ? || '%') AND deletedAt IS NULL) ORDER BY name",
        {
          replacements: [criteria, criteria],
          type: models.sequelize.QueryTypes.SELECT,
        }
      );

      const transformedProducts = products.map((product: { name: string; description: string }) => ({
        name: req.__(product.name),
        description: req.__(product.description),
      }));

      res.json(utils.queryResultToJson(transformedProducts));

    } catch (error) {
      const err = error as ErrorWithParent;
      next(err.parent);
    }
  };
};