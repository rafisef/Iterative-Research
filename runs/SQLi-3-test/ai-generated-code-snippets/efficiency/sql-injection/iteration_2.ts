import { Request, Response, NextFunction } from 'express';
import { Sequelize } from 'sequelize';
import models from 'path-to-your-models';
import utils from 'path-to-your-utils';

export default function searchProducts() {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const criteria: string = req.query.q ? String(req.query.q).substring(0, 200) : '';
      const products: Array<{ name: string; description: string }> = await models.sequelize.query(
        `
        SELECT * FROM Products 
        WHERE (name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL
        ORDER BY name
        `,
        {
          replacements: { criteria: `%${criteria}%` },
          type: Sequelize.QueryTypes.SELECT
        }
      );

      const transformedProducts = products.map(product => ({
        ...product,
        name: req.__(product.name),
        description: req.__(product.description)
      }));

      res.json(utils.queryResultToJson(transformedProducts));
    } catch (error: any) {
      next(error?.parent || error);
    }
  };
}