package org.itstep.TrainWebApp.config;


import org.itstep.TrainWebApp.service.CustomerServiceBaseImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@ComponentScan("org.itstep.TrainWebApp")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private CustomerServiceBaseImpl customerService;

    @Autowired
    public void setCustomerService(CustomerServiceBaseImpl customerService) {
        this.customerService = customerService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()

                .antMatchers("/login", "/registration").anonymous()
                //.antMatchers("/", "/show").authenticated()
                //.antMatchers("/admin/**").hasRole("ADMIN")
                //.antMatchers("/", "/show").hasRole("USER")
                .anyRequest().authenticated()
                .and()
                //.csrf().disable()//Настройка для входа в систему
                .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/bus/")
                .loginProcessingUrl("/login/process")
                .failureForwardUrl("/login?error=true")
                .usernameParameter("username")
                .and().logout(logout -> logout
                .logoutSuccessUrl("/"));
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customerService).passwordEncoder(bCryptPasswordEncoder());
    }

    @Bean
    public PasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
