package com.springboot.security.api.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.security.api.student.model.Student;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

	private static final List<Student> STUDENTS = Arrays.asList(
			new Student(1, "James Bond"),
			new Student(3, "Maria Jones"), 
			new Student(2, "Anna Smith"));

	@GetMapping("{studentId}")
	public Student getStudent(@PathVariable("studentId") Integer studentId) {
		return STUDENTS.stream()
				.filter(s -> studentId.equals(s.getStudentId()))
				.findFirst()
				.orElseThrow(() -> new IllegalStateException("Student " + studentId + " doesn't exists"));
	}

}
