import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule } from '@nestjs/swagger';
import { readFileSync } from 'fs';
import { join } from 'path';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const allowedOrigins = (process.env.CORS_ORIGINS ?? 'http://localhost:3000')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  app.enableCors({
    origin: allowedOrigins,
    credentials: true,
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const swaggerPath = process.env.SWAGGER_PATH ?? '/api/docs';
  const swaggerFile = join(process.cwd(), 'swagger.json');
  const swaggerDocument = JSON.parse(readFileSync(swaggerFile, 'utf8'));
  SwaggerModule.setup(swaggerPath, app, swaggerDocument);

  await app.listen(process.env.PORT ?? 3001,'0.0.0.0');
}
bootstrap();
