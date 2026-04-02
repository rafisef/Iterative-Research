import { Request, Response, NextFunction } from 'express';
import { sequelize, QueryTypes } from './models';
import utils from './utils';

interface ErrorWithParent extends Error {
  parent: Error;
}

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawCriteria = req.query.q;
      const criteria = typeof rawCriteria === 'string' ? rawCriteria.slice(0, 200) : '';

      const products = await sequelize.query(
        "SELECT * FROM Products WHERE ((name LIKE '%' || $1 || '%' OR description LIKE '%' || $1 || '%') AND deletedAt IS NULL) ORDER BY name",
        {
          bind: [criteria],
          type: QueryTypes.SELECT,
        }
      );

      res.json(utils.queryResultToJson(products.map((product: { name: string; description: string }) => ({
        name: req.__(product.name),
        description: req.__(product.description),
      }))));

    } catch (error) {
      const err = error as ErrorWithParent;
      next(err.parent);
    }
  };
};