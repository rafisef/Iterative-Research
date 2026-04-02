import { Request, Response, NextFunction } from 'express';
import models from './models';
import utils from './utils';

interface ErrorWithParent extends Error {
  parent: Error;
}

module.exports = function searchProducts() {
  return (req: Request, res: Response, next: NextFunction) => {
    const rawCriteria = req.query.q;
    const criteria = typeof rawCriteria === 'string' && rawCriteria !== 'undefined' ? rawCriteria.slice(0, 200) : '';

    models.sequelize.query(
      "SELECT * FROM Products WHERE ((name LIKE '%' || ? || '%' OR description LIKE '%' || ? || '%') AND deletedAt IS NULL) ORDER BY name",
      {
        replacements: [criteria, criteria],
        type: models.sequelize.QueryTypes.SELECT,
      }
    )
    .then((products: Array<{ name: string; description: string }>) => {
      const transformedProducts = products.map(product => ({
        name: req.__(product.name),
        description: req.__(product.description),
      }));
      res.json(utils.queryResultToJson(transformedProducts));
    })
    .catch((error: ErrorWithParent) => {
      next(error.parent);
    });
  };
};