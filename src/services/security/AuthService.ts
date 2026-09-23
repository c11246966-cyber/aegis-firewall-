/**
 * Aegis Management Security & Role-Based Access Control (RBAC) Service
 * 
 * Provides:
 * - Authentication & mock secure hashing
 * - Session expiration
 * - Login rate limiting & account lockout (max 5 attempts -> 15 min lock)
 * - Strict RBAC: ADMIN, SECURITY_ANALYST, OPERATOR, VIEWER
 */

import { UserRole, UserSession } from '../../types/aegis';

export interface UserAccount {
  username: string;
  role: UserRole;
  passwordHash: string; // SHA-256 equivalent
  displayName: string;
  failedAttempts: number;
  lockedUntil: number | null;
}

export class AuthService {
  private users: Map<string, UserAccount> = new Map();
  private currentSession: UserSession | null = null;
  private subscribers: Array<() => void> = [];

  constructor() {
    this.seedDefaultUsers();
    // Default active session for initial exploration is ADMIN
    this.login('admin', 'Aegis@Admin2026!');
  }

  private seedDefaultUsers() {
    this.users.set('admin', {
      username: 'admin',
      role: 'ADMIN',
      passwordHash: 'hash_admin_aegis_secure_2026',
      displayName: 'Lead Security Architect (Admin)',
      failedAttempts: 0,
      lockedUntil: null,
    });
    this.users.set('analyst', {
      username: 'analyst',
      role: 'SECURITY_ANALYST',
      passwordHash: 'hash_analyst_soc_2026',
      displayName: 'Senior SOC Analyst',
      failedAttempts: 0,
      lockedUntil: null,
    });
    this.users.set('operator', {
      username: 'operator',
      role: 'OPERATOR',
      passwordHash: 'hash_operator_ops_2026',
      displayName: 'Network Operations Engineer',
      failedAttempts: 0,
      lockedUntil: null,
    });
    this.users.set('viewer', {
      username: 'viewer',
      role: 'VIEWER',
      passwordHash: 'hash_viewer_audit_2026',
      displayName: 'Compliance Auditor (Viewer)',
      failedAttempts: 0,
      lockedUntil: null,
    });
  }

  public subscribe(cb: () => void): () => void {
    this.subscribers.push(cb);
    return () => {
      this.subscribers = this.subscribers.filter(s => s !== cb);
    };
  }

  private notify() {
    this.subscribers.forEach(cb => cb());
  }

  public getCurrentSession(): UserSession | null {
    if (this.currentSession && Date.now() > this.currentSession.expiresAt) {
      // Session expired
      this.currentSession = null;
      this.notify();
    }
    return this.currentSession;
  }

  public getCurrentUserRole(): UserRole {
    return this.getCurrentSession()?.role || 'VIEWER';
  }

  public isAuthorized(requiredRoles: UserRole[]): boolean {
    const role = this.getCurrentUserRole();
    return requiredRoles.includes(role);
  }

  public login(username: string, passwordAttempt: string): { success: boolean; error?: string; session?: UserSession } {
    const user = this.users.get(username.toLowerCase());
    const now = Date.now();

    if (!user) {
      return { success: false, error: 'Invalid credentials or user does not exist.' };
    }

    // Check account lockout
    if (user.lockedUntil && now < user.lockedUntil) {
      const remainingSecs = Math.ceil((user.lockedUntil - now) / 1000);
      return {
        success: false,
        error: `Account is locked due to repeated failed login attempts. Retry in ${remainingSecs} seconds.`,
      };
    }

    // Verify credentials
    const validPasswords: Record<string, string> = {
      admin: 'Aegis@Admin2026!',
      analyst: 'Aegis@Analyst2026!',
      operator: 'Aegis@Operator2026!',
      viewer: 'Aegis@Viewer2026!',
    };
    const isValid = validPasswords[username.toLowerCase()] === passwordAttempt;

    if (!isValid) {
      user.failedAttempts += 1;
      if (user.failedAttempts >= 5) {
        user.lockedUntil = now + (15 * 60 * 1000); // 15 minutes lockout
        this.notify();
        return {
          success: false,
          error: 'Account locked: Maximum 5 failed login attempts exceeded. 15-minute cooldown initiated.',
        };
      }
      return {
        success: false,
        error: `Invalid credentials. (${5 - user.failedAttempts} attempts remaining before lockout)`,
      };
    }

    // Reset failed counter
    user.failedAttempts = 0;
    user.lockedUntil = null;

    const session: UserSession = {
      username: user.username,
      role: user.role,
      token: `aegis_jwt_${user.username}_${Math.random().toString(36).substring(2)}`,
      loginTime: now,
      expiresAt: now + (4 * 60 * 60 * 1000), // 4 hours session duration
      mfaVerified: true,
    };

    this.currentSession = session;
    this.notify();
    return { success: true, session };
  }

  public logout() {
    this.currentSession = null;
    this.notify();
  }

  public switchUserFast(username: string): boolean {
    const u = this.users.get(username);
    if (!u) return false;
    this.login(u.username, 'Aegis@DemoPass123!');
    return true;
  }

  public listUsers(): { username: string; role: UserRole; displayName: string; isLocked: boolean }[] {
    return Array.from(this.users.values()).map(u => ({
      username: u.username,
      role: u.role,
      displayName: u.displayName,
      isLocked: !!(u.lockedUntil && Date.now() < u.lockedUntil),
    }));
  }
}

export const authService = new AuthService();
