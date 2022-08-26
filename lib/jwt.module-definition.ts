import { ConfigurableModuleBuilder } from '@nestjs/common';
import { JwtModuleOptions } from './interfaces';

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN } =
  new ConfigurableModuleBuilder<JwtModuleOptions>()
    .setFactoryMethodName('createJwtOptions')
    .build();
