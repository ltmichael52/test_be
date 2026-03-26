import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { readFileSync } from 'fs';

import { v4 as uuidv4 } from 'uuid';
import nodemailer, { Transporter } from 'nodemailer';
import { Account } from './entities/account.entity';
import { UserProfile } from './entities/user-profile.entity';
import { RevokedToken } from './entities/revoked-token.entity';
import { Session } from './entities/session.entity';
import { EmailVerification } from './entities/email-verification.entity';
import { SignUpDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { VerifyEmailQueryDto } from './dto/verify-email.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { LogoutDto } from './dto/logout.dto';

interface TokenPayload {
  sub: string;
  accountId: string;
  email: string;
  role: string;
  tokenType: 'access' | 'refresh';
  jti: string;
}

@Injectable()
export class AuthService {
  private readonly privateKey: string;
  private readonly publicKey: string;
  private readonly transporter: Transporter;
  private readonly accessExpiresIn: string;
  private readonly refreshExpiresIn: string;
  private readonly emailVerifyExpiresMin: number;
  private readonly resendCooldownSec: number;
  private readonly frontendUrl: string;

  constructor(
    @InjectRepository(Account)
    private readonly accountRepository: Repository<Account>,
    @InjectRepository(UserProfile)
    private readonly userProfileRepository: Repository<UserProfile>,
    @InjectRepository(RevokedToken)
    private readonly revokedTokenRepository: Repository<RevokedToken>,
    @InjectRepository(Session)
    private readonly sessionRepository: Repository<Session>,
    @InjectRepository(EmailVerification)
    private readonly emailVerificationRepository: Repository<EmailVerification>,
    private readonly jwtService: JwtService,
  ) {
    this.privateKey = this.loadKey(
      process.env.JWT_PRIVATE_KEY_BASE64,
      process.env.JWT_PRIVATE_KEY_PATH ??
        '',
    );
    this.publicKey = this.loadKey(
      process.env.JWT_PUBLIC_KEY_BASE64,
      process.env.JWT_PUBLIC_KEY_PATH ??
        '',
    );

    this.accessExpiresIn = process.env.JWT_ACCESS_EXPIRES_IN ?? '15m';
    this.refreshExpiresIn = process.env.JWT_REFRESH_EXPIRES_IN ?? '7d';
    this.emailVerifyExpiresMin = Number(
      process.env.EMAIL_VERIFY_EXPIRES_MIN ?? 30,
    );
    this.resendCooldownSec = Number(
      process.env.EMAIL_RESEND_COOLDOWN_SEC ?? 30,
    );
    this.frontendUrl = process.env.FRONTEND_URL ?? 'http://localhost:3000';

    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT ?? 465),
      secure: String(process.env.SMTP_SECURE ?? 'true') === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }

  async signUp(dto: SignUpDto) {
    const email = dto.email.trim().toLowerCase();
    if (dto.password !== dto.confirmPassword) {
      throw new BadRequestException('Password confirmation does not match');
    }

    const existing = await this.accountRepository.findOne({ where: { email } });
    if (existing) {
      throw new BadRequestException('Email already exists');
    }

    const passwordHash = await bcrypt.hash(dto.password, 10);
    const account = this.accountRepository.create({
      email,
      passwordHash,
      role: 'user',
      status: 'pending',
    });

    const savedAccount = await this.accountRepository.save(account);

    const profile = this.userProfileRepository.create({
      accountId: savedAccount.accountId,
      fullName: dto.fullName,
      totalQuestions: 0,
      totalContributions: 0,
    });

    await this.userProfileRepository.save(profile);

    const token = this.generateVerificationToken();
    const expiresAt = this.addMinutes(new Date(), this.emailVerifyExpiresMin);
    await this.emailVerificationRepository.save({
      accountId: savedAccount.accountId,
      token,
      expiresAt,
    });

    await this.sendVerificationEmail(email, token);

    return {
      message: 'Account created. Please verify your email.',
    };
  }

  async resendVerification(dto: ResendVerificationDto) {
    const email = dto.email.trim().toLowerCase();
    const account = await this.accountRepository.findOne({ where: { email } });
    if (!account) {
      throw new BadRequestException('Account not found');
    }

    if (account.status === 'active') {
      throw new BadRequestException('Account already active');
    }

    const latest = await this.emailVerificationRepository.findOne({
      where: { accountId: account.accountId },
      order: { createdAt: 'DESC' },
    });

    if (latest) {
      const nextAllowed = this.addSeconds(
        latest.createdAt,
        this.resendCooldownSec,
      );
      if (nextAllowed > new Date()) {
        throw new BadRequestException('Please wait before requesting a new code');
      }
    }

    const token = this.generateVerificationToken();
    const expiresAt = this.addMinutes(new Date(), this.emailVerifyExpiresMin);
    await this.emailVerificationRepository.save({
      accountId: account.accountId,
      token,
      expiresAt,
    });

    await this.sendVerificationEmail(email, token);

    return { message: 'Verification email sent' };
  }

  async verifyEmail(dto: VerifyEmailQueryDto) {
    const verification = await this.emailVerificationRepository.findOne({
      where: { token: dto.token },
    });

    if (!verification || verification.expiresAt <= new Date()) {
      throw new BadRequestException('Invalid or expired verification link');
    }

    const account = await this.accountRepository.findOne({
      where: { accountId: verification.accountId },
    });
    if (!account) {
      throw new BadRequestException('Account not found');
    }

    account.status = 'active';
    await this.accountRepository.save(account);

    await this.emailVerificationRepository.delete({ accountId: account.accountId });

    return { message: 'Email verified successfully' };
  }

  async login(dto: LoginDto) {
    const email = dto.email.trim().toLowerCase();
    const account = await this.accountRepository.findOne({ where: { email } });
    if (!account) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const passwordValid = await bcrypt.compare(dto.password, account.passwordHash);
    if (!passwordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (account.status !== 'active') {
      throw new ForbiddenException({
        statusCode: 403,
        message: 'Tài khoản chưa được xác thực. Vui lòng kiểm tra email.',
        needsVerification: true,
        email: account.email,
      });
    }

    const profile = await this.userProfileRepository.findOne({
      where: { accountId: account.accountId },
    });

    if (profile) {
      profile.lastLoginAt = new Date();
      await this.userProfileRepository.save(profile);
    }

    const accessToken = await this.createAccessToken(account, profile?.userId);
    const refreshToken = await this.createRefreshToken(account);

    await this.sessionRepository.save({
      accountId: account.accountId,
      refreshToken: refreshToken.token,
      expiresIn: refreshToken.expiresIn,
      expiresAt: refreshToken.expiresAt,
      status: 'active',
    });

    return {
      accessToken: accessToken.token,
      accessTokenExpiresAt: accessToken.expiresAt,
      refreshToken: refreshToken.token,
      refreshTokenExpiresAt: refreshToken.expiresAt,
      role: account.role,
    };
  }

  async refresh(dto: RefreshTokenDto) {
    const payload = this.verifyToken(dto.refreshToken);
    if (payload.tokenType !== 'refresh') {
      throw new UnauthorizedException('Invalid token type');
    }

    const revoked = await this.revokedTokenRepository.findOne({
      where: { jti: payload.jti },
    });
    if (revoked) {
      throw new UnauthorizedException('Token revoked');
    }

    const session = await this.sessionRepository.findOne({
      where: { refreshToken: dto.refreshToken, status: 'active' },
    });
    if (!session || session.expiresAt <= new Date()) {
      throw new UnauthorizedException('Invalid session');
    }

    const account = await this.accountRepository.findOne({
      where: { accountId: payload.accountId },
    });
    if (!account || account.status !== 'active') {
      throw new UnauthorizedException('Account not active');
    }

    await this.revokedTokenRepository.save({
      accountId: payload.accountId,
      jti: payload.jti,
      tokenType: 'refresh',
      expiresAt: new Date(payload.exp * 1000),
      reason: 'rotated',
    });

    const accessToken = await this.createAccessToken(account, payload.sub);
    const newRefreshToken = await this.createRefreshToken(account);

    session.refreshToken = newRefreshToken.token;
    session.expiresAt = newRefreshToken.expiresAt;
    session.expiresIn = newRefreshToken.expiresIn;
    await this.sessionRepository.save(session);

    return {
      accessToken: accessToken.token,
      accessTokenExpiresAt: accessToken.expiresAt,
      refreshToken: newRefreshToken.token,
      refreshTokenExpiresAt: newRefreshToken.expiresAt,
    };
  }

  async logout(accessToken: string, dto: LogoutDto) {
    if (!accessToken) {
      throw new BadRequestException('Access token required');
    }

    const accessPayload = this.verifyToken(accessToken);
    if (accessPayload.tokenType !== 'access') {
      throw new UnauthorizedException('Invalid access token');
    }

    await this.revokedTokenRepository.save({
      accountId: accessPayload.accountId,
      jti: accessPayload.jti,
      tokenType: 'access',
      expiresAt: new Date(accessPayload.exp * 1000),
      reason: 'logout',
    });

    if (dto.refreshToken) {
      const refreshPayload = this.verifyToken(dto.refreshToken);
      await this.revokedTokenRepository.save({
        accountId: refreshPayload.accountId,
        jti: refreshPayload.jti,
        tokenType: 'refresh',
        expiresAt: new Date(refreshPayload.exp * 1000),
        reason: 'logout',
      });

      const session = await this.sessionRepository.findOne({
        where: { refreshToken: dto.refreshToken },
      });
      if (session) {
        session.status = 'revoked';
        await this.sessionRepository.save(session);
      }
    }

    return { message: 'Logged out' };
  }

  async isTokenRevoked(token: string) {
    const payload = this.verifyToken(token);
    const revoked = await this.revokedTokenRepository.findOne({
      where: { jti: payload.jti },
    });
    return Boolean(revoked);
  }

  private verifyToken(token: string) {
    return this.jwtService.verify<TokenPayload & { exp: number }>(token, {
      publicKey: this.publicKey,
      algorithms: ['RS256'],
    });
  }

  private async createAccessToken(account: Account, userId?: string) {
    const jti = uuidv4();
    const payload: TokenPayload = {
      sub: userId ?? account.accountId,
      accountId: account.accountId,
      email: account.email,
      role: account.role,
      tokenType: 'access',
      jti,
    };

    const token = await this.jwtService.signAsync(payload, {
      privateKey: this.privateKey,
      algorithm: 'RS256',
      expiresIn: this.parseDurationToSeconds(this.accessExpiresIn),
    });

    return {
      token,
      jti,
      expiresAt: this.addSeconds(
        new Date(),
        this.parseDurationToSeconds(this.accessExpiresIn),
      ),
    };
  }

  private async createRefreshToken(account: Account) {
    const jti = uuidv4();
    const payload: TokenPayload = {
      sub: account.accountId,
      accountId: account.accountId,
      email: account.email,
      role: account.role,
      tokenType: 'refresh',
      jti,
    };

    const expiresIn = this.parseDurationToSeconds(this.refreshExpiresIn);
    const token = await this.jwtService.signAsync(payload, {
      privateKey: this.privateKey,
      algorithm: 'RS256',
      expiresIn,
    });

    return {
      token,
      jti,
      expiresIn,
      expiresAt: this.addSeconds(new Date(), expiresIn),
    };
  }

  private async sendVerificationEmail(email: string, token: string) {
    const from = process.env.SMTP_FROM ?? process.env.SMTP_USER ?? '';
    const subject = 'YHCT - Xác thực tài khoản';
    const verifyUrl = `${this.frontendUrl}/verify-email?token=${encodeURIComponent(token)}`;

    const html = `
      <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px;background:#f8faf9;border-radius:12px">
        <div style="text-align:center;margin-bottom:24px">
          <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#7de0b0;margin-right:8px"></span>
          <span style="font-size:14px;color:#6b7c70;letter-spacing:0.15em">YHCT</span>
        </div>
        <h1 style="font-size:22px;color:#1b1f1c;text-align:center;margin:0 0 16px">Xác thực tài khoản</h1>
        <p style="font-size:14px;color:#4a5a50;text-align:center;margin:0 0 28px;line-height:1.6">
          Cảm ơn bạn đã đăng ký. Nhấn nút bên dưới để xác thực email của bạn.
        </p>
        <div style="text-align:center;margin-bottom:28px">
          <a href="${verifyUrl}" style="display:inline-block;padding:12px 36px;background:#1b1f1c;color:#ffffff;text-decoration:none;border-radius:8px;font-size:14px;font-weight:600">
            Xác thực email
          </a>
        </div>
        <p style="font-size:12px;color:#8a9a90;text-align:center;margin:0;line-height:1.5">
          Nếu nút không hoạt động, sao chép link này vào trình duyệt:<br/>
          <a href="${verifyUrl}" style="color:#7de0b0;word-break:break-all">${verifyUrl}</a>
        </p>
        <p style="font-size:11px;color:#b0b8b3;text-align:center;margin:20px 0 0">
          Link này sẽ hết hạn sau ${this.emailVerifyExpiresMin} phút.
        </p>
      </div>
    `;

    await this.transporter.sendMail({
      to: email,
      from,
      subject,
      html,
      text: `Xác thực tài khoản: ${verifyUrl}`,
    });
  }

  private generateVerificationToken() {
    return uuidv4();
  }

  private loadKey(base64: string | undefined, path: string) {
    if (base64) {
      return Buffer.from(base64, 'base64').toString('utf8');
    }

    return readFileSync(path, 'utf8');
  }

  private parseDurationToSeconds(value: string) {
    const match = value.match(/^(\d+)([smhd])$/i);
    if (!match) {
      return Number(value) || 0;
    }

    const amount = Number(match[1]);
    const unit = match[2].toLowerCase();

    switch (unit) {
      case 's':
        return amount;
      case 'm':
        return amount * 60;
      case 'h':
        return amount * 3600;
      case 'd':
        return amount * 86400;
      default:
        return amount;
    }
  }

  private addMinutes(date: Date, minutes: number) {
    return new Date(date.getTime() + minutes * 60 * 1000);
  }

  private addSeconds(date: Date, seconds: number) {
    return new Date(date.getTime() + seconds * 1000);
  }
}
