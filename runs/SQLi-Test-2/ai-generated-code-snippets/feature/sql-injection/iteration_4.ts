import { Request, Response, NextFunction } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';
import { utils, models } from './utils';
import fs from 'fs';
import path from 'path';

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

interface Storage {
  searchProducts(criteria: string): Promise<any[]>;
}

class DatabaseStorage implements Storage {
  private sequelize: Sequelize;

  constructor(sequelize: Sequelize) {
    this.sequelize = sequelize;
  }

  async searchProducts(criteria: string): Promise<any[]> {
    const [products] = await this.sequelize.query(
      "SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name",
      {
        replacements: { criteria: `%${criteria}%` },
        type: QueryTypes.SELECT
      }
    ) as [any[], unknown];
    return products;
  }
}

class FileStorage implements Storage {
  private filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  async searchProducts(criteria: string): Promise<any[]> {
    const data = fs.readFileSync(this.filePath, 'utf-8');
    const products = JSON.parse(data) as any[];
    return products.filter(product =>
      (product.name.includes(criteria) || product.description.includes(criteria)) && !product.deletedAt
    );
  }
}

interface UserSession {
  userId: string;
  sessionId: string;
}

class SessionManager {
  private sessions: Map<string, UserSession> = new Map();

  createSession(userId: string): string {
    const sessionId = this.generateSessionId();
    this.sessions.set(sessionId, { userId, sessionId });
    return sessionId;
  }

  validateSession(sessionId: string): boolean {
    return this.sessions.has(sessionId);
  }

  private generateSessionId(): string {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }
}

module.exports = function searchProducts(
  authProviders: AuthProvider[] = [new BasicAuthProvider()],
  storage: Storage = new DatabaseStorage(models.sequelize),
  sessionManager: SessionManager = new SessionManager()
) {
  return async (req: Request, res: Response, next: NextFunction) => {
    let isAuthenticated = false;
    let sessionId: string | undefined;

    for (const provider of authProviders) {
      if (await provider.authenticate(req)) {
        isAuthenticated = true;
        sessionId = sessionManager.createSession(req.ip);
        break;
      }
    }

    if (!isAuthenticated || !sessionId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!sessionManager.validateSession(sessionId)) {
      return res.status(401).json({ error: 'Invalid session' });
    }

    let criteria: string = req.query.q === 'undefined' ? '' : (req.query.q as string) ?? '';
    criteria = criteria.length <= 200 ? criteria : criteria.substring(0, 200);

    try {
      const products = await storage.searchProducts(criteria);

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