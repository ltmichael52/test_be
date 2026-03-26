import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { Account } from './auth/entities/account.entity';
import { EmailVerification } from './auth/entities/email-verification.entity';
import { RevokedToken } from './auth/entities/revoked-token.entity';
import { Session } from './auth/entities/session.entity';
import { UserProfile } from './auth/entities/user-profile.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRoot({
      type: 'mssql',
      host: process.env.DB_HOST ?? '',
      port: Number(process.env.DB_PORT ?? 1433),
      username: process.env.DB_USERNAME ?? '',
      password: process.env.DB_PASSWORD ?? '',
      database: process.env.DB_NAME ?? 'YHCT_DB',
      entities: [Account, UserProfile, RevokedToken, EmailVerification, Session],
      synchronize: false,
      options: {
        encrypt: true,
        trustServerCertificate: true,
      },
    }),
    AuthModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
