import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import appConfig from './config/app.config';
import authConfig from './config/auth.config';
import databaseConfig from './config/database.config';
import { AuthModule } from './modules/auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfig, authConfig, databaseConfig],
    }),

    // MongoDB connection using database config
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => {
        const dbConfig = configService.get('database'); // loads database config
        return {
          uri: dbConfig.mongoUrl,
          ...dbConfig.options,
        };
      },
    }),

    AuthModule,
  ],
})
export class AppModule {}

// import { Module } from '@nestjs/common';
// import { MongooseModule } from '@nestjs/mongoose';
// import { ConfigModule, ConfigService } from '@nestjs/config';
// import { AppController } from './app.controller';
// import { AppService } from './app.service';
// import { AuthModule } from './modules/auth/auth.module';

// @Module({
//   imports: [
//     ConfigModule.forRoot({ isGlobal: true }),
//     MongooseModule.forRootAsync({
//       imports: [ConfigModule],
//       inject: [ConfigService],
//       useFactory: async (configService: ConfigService) => {
//         const mongoUrl = configService.get<string>('MONGO_URL');
//         console.log(mongoUrl);
//         if (!mongoUrl) {
//           console.error('MONGO_URL is missing');
//           process.exit(1); // Stop app
//         }
//         return {
//           uri: mongoUrl,
//           useNewUrlParser: true,
//           useUnifiedTopology: true,
//         };
//       },
//     }),
//     AuthModule,
//   ],
//   controllers: [AppController],
//   providers: [AppService],
// })
// export class AppModule {}

// import { Module } from '@nestjs/common';
// import { AppController } from './app.controller';
// import { AppService } from './app.service';
// import { MongooseModule } from '@nestjs/mongoose';
// import { AuthModule } from './modules/auth/auth.module';

// @Module({
//   imports: [
//     MongooseModule.forRoot('mongodb://localhost:27017/mdht'),
//     AuthModule,
//   ],
//   controllers: [AppController],
//   providers: [AppService],
// })
// export class AppModule {}
