import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';
import { utils, models } from './utils'; // Assuming utils and models are imported from a utils module

type ErrorWithParent = Error & { parent?: Error };

interface AuthProvider {
  authenticate(req: Request): Promise<boolean>;
}

class BasicAuthProvider implements AuthProvider {
  async authenticate(req: Request): Promise<boolean> {
    // Basic authentication logic here
    return true;
  }
}

class OAuthProvider implements AuthProvider {
  async authenticate(req: Request): Promise<boolean> {
    // OAuth authentication logic here
    return true;
  }
}

module.exports = function searchProducts(authProviders: AuthProvider[] = [new BasicAuthProvider()]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    let isAuthenticated = false;
    for (const provider of authProviders) {
      if (await provider.authenticate(req)) {
        isAuthenticated = true;
        break;
      }
    }

    if (!isAuthenticated) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    let criteria: string = req.query.q === 'undefined' ? '' : (req.query.q as string) ?? '';
    criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

    try {
      const [products] = await models.sequelize.query(
        "SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name",
        {
          replacements: { criteria: `%${criteria}%` },
          type: QueryTypes.SELECT
        }
      ) as [any[], unknown];

      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name);
        products[i].description = req.__(products[i].description);
      }

      res.json(utils.queryResultToJson(products));
    } catch (error) {
      next((error as ErrorWithParent).parent);
    }
  };
};