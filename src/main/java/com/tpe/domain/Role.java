package com.tpe.domain;


import com.tpe.domain.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity()
@Table(name = "tbl_role")
public class Role {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(length = 25,nullable = false)
      //  private String name;//ADMIN,STUDENT // admin/ Admin, Student //0
    @Enumerated(EnumType.STRING)
    ////This annotation is useful when you want to store the string representation of enum constants in the database
    private UserRole name;

    //toString

    @Override
    public String toString() {
        return "Role{" +
                "name=" + name +
                '}';
    }



}
