import { Request, Response, NextFunction } from 'express';
import { Sequelize } from 'sequelize';

interface ErrorWithParent extends Error {
  parent: Error;
}

const models = {
  sequelize: new Sequelize('database', 'username', 'password', {
    dialect: 'mysql',
  }),
};

const utils = {
  queryResultToJson: (results: any[]): any => results,
};

module.exports = function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawCriteria = req.query.q;
      const criteria: string = typeof rawCriteria === 'string' ? rawCriteria.substring(0, 200) : '';
      const products: any[] = await models.sequelize.query(
        "SELECT * FROM Products WHERE (name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL ORDER BY name",
        { replacements: { criteria: `%${criteria}%` }, type: models.sequelize.QueryTypes.SELECT }
      );

      const translatedProducts = products.map(product => ({
        ...product,
        name: req.__(product.name),
        description: req.__(product.description),
      }));

      res.json(utils.queryResultToJson(translatedProducts));
    } catch (error: any) {
      next(error.parent);
    }
  };
}