package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class DemoSecurityConfig {
    //add support for JDBC, NO HARDCODED USER
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManager jdbcUserDetailmanager = new JdbcUserDetailsManager(dataSource);

        //define query to retrieve a user by username
        jdbcUserDetailmanager.setUsersByUsernameQuery("select user_id, pw, active from members where user_id=?");
        //define query to retrieve the authorities/roles by username
//        jdbcUserDetailmanager.setUsersByUsernameQuery(
//                "select user_id, role from roles where user_id=?"
//        );
        jdbcUserDetailmanager.setAuthoritiesByUsernameQuery("select user_id, role from roles where user_id=?");

        return  jdbcUserDetailmanager;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(configurer ->
                configurer
                        .requestMatchers(HttpMethod.GET,"/api/employees").hasRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.GET,"/api/employees/**").hasRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.POST,"/api/employees").hasRole("MANAGER")
                        .requestMatchers(HttpMethod.PUT,"/api/employees").hasRole("MANAGER")
//                        .requestMatchers(HttpMethod.PUT,"/api/employees").hasRole("MANAGER") //if we are using SPRING DATA REST
                        .requestMatchers(HttpMethod.DELETE,"/api/employees/**").hasRole("ADMIN")

        );
        // TELL SPRING we are using HTTP basic configuration
        http.httpBasic(Customizer.withDefaults());

        //disable cross site request forgery (CSRF)
        //In genera, not required for stateless REST APIs taht use POST,PUT, DELETE and/or PATCH
        http.csrf(csrf->csrf.disable());
        return http.build();


//    @Bean
//    public InMemoryUserDetailsManager userDetailsManager() {
//        UserDetails john = User.builder()
//                .username("john")
//                .password("{noop}test123")
//                .roles("EMPLOYEE")
//                .build();
//        UserDetails mary = User.builder()
//                .username("mary")
//                .password("{noop}test123")
//                .roles("EMPLOYEE","MANAGER")
//                .build();
//        UserDetails SUZAN = User.builder()
//                .username("suzan")
//                .password("{noop}test123")
//                .roles("EMPLOYEE","MANAGER","ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(john, mary, SUZAN);
//    }
    }
}
